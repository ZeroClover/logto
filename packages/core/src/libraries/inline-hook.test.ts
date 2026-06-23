import { LogtoInlineHookKey } from '@logto/schemas';

import { EnvSet } from '#src/env-set/index.js';
import { LocalVmError } from '#src/utils/custom-jwt/index.js';

import {
  getInlineHookExecutionErrorPolicyDecision,
  InlineHookLibrary,
  isAccessDeniedError,
} from './inline-hook.js';
import type {
  InlineHookAccessDeniedError,
  InlineHookExecutionErrorFallback,
  InlineHookExecutionErrorPolicyDecision,
} from './inline-hook.js';
import type { LogtoConfigLibrary } from './logto-config.js';

const { jest } = import.meta;

const originalIsDevFeaturesEnabled = EnvSet.values.isDevFeaturesEnabled;
const getInlineHook = jest.fn() as jest.MockedFunction<LogtoConfigLibrary['getInlineHook']>;
const library = new InlineHookLibrary({ getInlineHook } as unknown as LogtoConfigLibrary);

const setDevFeaturesEnabled = (isDevFeaturesEnabled: boolean) => {
  Reflect.set(EnvSet.values, 'isDevFeaturesEnabled', isDevFeaturesEnabled);
};

describe('InlineHookLibrary', () => {
  beforeEach(() => {
    setDevFeaturesEnabled(true);
  });

  afterEach(() => {
    jest.clearAllMocks();
    setDevFeaturesEnabled(originalIsDevFeaturesEnabled);
  });

  it('loads hook config and runs enabled inline hook script in local VM', async () => {
    getInlineHook.mockResolvedValueOnce({
      enabled: true,
      environmentVariables: {
        NAME_SUFFIX: ' updated',
      },
      script: `
        const runInlineHook = ({ event, environmentVariables, api }) => ({
          action: 'updateUser',
          user: {
            name: event.user.name + environmentVariables.NAME_SUFFIX,
          },
          apiFrozen: Object.isFrozen(api),
        });
      `,
    });

    await expect(
      library.runHook({
        key: LogtoInlineHookKey.PostSignIn,
        event: {
          key: LogtoInlineHookKey.PostSignIn,
          interactionEvent: 'SignIn',
          user: {
            id: 'foo',
            name: 'Foo',
          },
        },
      })
    ).resolves.toEqual({
      action: 'updateUser',
      user: {
        name: 'Foo updated',
      },
      apiFrozen: true,
    });

    expect(getInlineHook).toHaveBeenCalledWith(LogtoInlineHookKey.PostSignIn);
  });

  it('does not load or run hooks when dev features are disabled', async () => {
    setDevFeaturesEnabled(false);

    await expect(
      library.runHook({
        key: LogtoInlineHookKey.PostSignIn,
        event: {},
      })
    ).resolves.toBeUndefined();

    expect(getInlineHook).not.toHaveBeenCalled();
  });

  it('does not run disabled hooks', async () => {
    getInlineHook.mockResolvedValueOnce({
      enabled: false,
      script: `
        const runInlineHook = () => {
          throw new Error('should not run');
        };
      `,
    });

    await expect(
      library.runHook({
        key: LogtoInlineHookKey.PostSignIn,
        event: {},
      })
    ).resolves.toBeUndefined();
  });

  it('throws LocalVmError when inline hook denies access', async () => {
    const script = `
      const runInlineHook = ({ api }) => api.denyAccess('Nope');
    `;

    await expect(
      InlineHookLibrary.runScriptInLocalVm({
        script,
        event: {},
      })
    ).rejects.toBeInstanceOf(LocalVmError);

    try {
      await InlineHookLibrary.runScriptInLocalVm({
        script,
        event: {},
      });
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(LocalVmError);
      await expect((error as LocalVmError).response.json()).resolves.toEqual({
        message: 'Nope',
        error: {
          code: 'AccessDenied',
          message: 'Nope',
        },
      });
    }
  });

  it('identifies inline hook AccessDenied errors', () => {
    const accessDeniedError: InlineHookAccessDeniedError = {
      code: 'AccessDenied',
      message: 'Nope',
    };

    expect(isAccessDeniedError(accessDeniedError)).toBe(true);
    expect(isAccessDeniedError({ code: 'LocalVmTimeout', message: 'Timed out' })).toBe(false);
  });

  it('maps inline hook AccessDenied to hook-specific RequestError', async () => {
    getInlineHook.mockResolvedValueOnce({
      enabled: true,
      script: `
        const runInlineHook = ({ api }) => api.denyAccess('Nope');
      `,
    });

    await expect(
      library.runHook({
        key: LogtoInlineHookKey.PostSignIn,
        event: {},
      })
    ).rejects.toMatchObject({
      code: 'session.hook_denied_access',
      status: 403,
    });

    getInlineHook.mockResolvedValueOnce({
      enabled: true,
      script: `
        const runInlineHook = ({ api }) => api.denyAccess('Nope');
      `,
    });

    await expect(
      library.runHook({
        key: LogtoInlineHookKey.PostFirstFactorVerification,
        event: {},
      })
    ).rejects.toMatchObject({
      code: 'session.invalid_credentials',
      status: 403,
    });
  });

  it('maps direct AccessDenied error bodies to RequestError decisions', async () => {
    const decision = await getInlineHookExecutionErrorPolicyDecision({
      key: LogtoInlineHookKey.PostSignIn,
      error: {
        code: 'AccessDenied',
        message: 'Nope',
      },
      onExecutionError: 'allow',
    });

    expect(decision.action).toBe('throw');
    if (decision.action !== 'throw') {
      throw new Error('Expected throw decision');
    }
    expect(decision.error).toMatchObject({
      code: 'session.hook_denied_access',
      status: 403,
    });
  });

  it('blocks inline hook execution errors by default', async () => {
    getInlineHook.mockResolvedValueOnce({
      enabled: true,
      script: `
        const runInlineHook = () => {
          throw new Error('Broken');
        };
      `,
    });

    await expect(
      library.runHook({
        key: LogtoInlineHookKey.PostSignIn,
        event: {},
      })
    ).rejects.toMatchObject({
      code: 'session.hook_denied_access',
      status: 403,
    });
  });

  it('allows PostSignIn execution errors to continue without hook enrichment', async () => {
    getInlineHook.mockResolvedValueOnce({
      enabled: true,
      onExecutionError: 'allow',
      script: `
        const runInlineHook = () => {
          throw new Error('Broken');
        };
      `,
    });

    await expect(
      library.runHook({
        key: LogtoInlineHookKey.PostSignIn,
        event: {},
      })
    ).resolves.toBeUndefined();
  });

  it('keeps PostFirstFactorVerification allow-mode errors from granting access', async () => {
    const decision = await getInlineHookExecutionErrorPolicyDecision({
      key: LogtoInlineHookKey.PostFirstFactorVerification,
      error: new Error('Broken'),
      onExecutionError: 'allow',
    });
    const expectedDecision: InlineHookExecutionErrorFallback = {
      action: 'rejectInvalidCredentials',
    };

    expect(decision).toEqual(expectedDecision);
  });

  it('returns RequestError decision for block-mode execution errors', async () => {
    const decision: InlineHookExecutionErrorPolicyDecision =
      await getInlineHookExecutionErrorPolicyDecision({
        key: LogtoInlineHookKey.PostSignIn,
        error: new Error('Broken'),
        onExecutionError: 'block',
      });

    expect(decision.action).toBe('throw');
    if (decision.action !== 'throw') {
      throw new Error('Expected throw decision');
    }
    expect(decision.error).toMatchObject({
      code: 'session.hook_denied_access',
      status: 403,
    });
  });
});
