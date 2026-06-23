import { LogtoInlineHookKey, type InlineHookExecutionErrorPolicy } from '@logto/schemas';
import { ResponseError } from '@withtyped/client';
import { z, ZodError } from 'zod';

import { EnvSet } from '#src/env-set/index.js';
import RequestError from '#src/errors/RequestError/index.js';
import type { LogtoConfigLibrary } from '#src/libraries/logto-config.js';
import {
  buildLocalVmErrorBody,
  LocalVmError,
  LocalVmTimeoutError,
  runScriptFunctionInLocalVm,
} from '#src/utils/custom-jwt/index.js';

const inlineHookFunctionName = 'runInlineHook';
const inlineHookAccessDeniedErrorCode = 'AccessDenied';
const defaultInlineHookExecutionErrorPolicy = 'block' satisfies InlineHookExecutionErrorPolicy;

const inlineHookAccessDeniedErrorGuard = z.object({
  code: z.literal(inlineHookAccessDeniedErrorCode),
  message: z.string(),
});

const inlineHookResponseErrorGuard = z.object({
  message: z.string(),
  error: z.unknown().optional(),
});

export type InlineHookAccessDeniedError = z.infer<typeof inlineHookAccessDeniedErrorGuard>;

export type InlineHookExecutionErrorFallback = {
  action: 'rejectInvalidCredentials';
};

export type InlineHookExecutionErrorPolicyDecision =
  | {
      action: 'throw';
      error: RequestError;
    }
  | {
      action: 'continue';
    }
  | InlineHookExecutionErrorFallback;

type InlineHookApiContext = {
  denyAccess: (message?: string) => never;
};

type InlineHookScriptPayload<Event> = {
  event: Event;
  environmentVariables?: Record<string, string>;
  api: InlineHookApiContext;
};

type InlineHookRunnerData<Event> = {
  script: string;
  event: Event;
  environmentVariables?: Record<string, string>;
};

type InlineHookExecutionErrorHandlingData = {
  key: LogtoInlineHookKey;
  error: unknown;
  onExecutionError?: InlineHookExecutionErrorPolicy;
};

const apiContext: InlineHookApiContext = Object.freeze({
  denyAccess: (message = 'Access denied') => {
    throw new LocalVmError(
      {
        message,
        error: {
          code: 'AccessDenied',
          message,
        },
      },
      403
    );
  },
});

export const isAccessDeniedError = (error: unknown): error is InlineHookAccessDeniedError =>
  inlineHookAccessDeniedErrorGuard.safeParse(error).success;

const getInlineHookDeniedErrorCode = (key: LogtoInlineHookKey) => {
  switch (key) {
    case LogtoInlineHookKey.PostFirstFactorVerification: {
      return 'session.invalid_credentials';
    }
    case LogtoInlineHookKey.PostSignIn: {
      return 'session.hook_denied_access';
    }
  }
};

const createInlineHookDeniedError = (key: LogtoInlineHookKey, status: number, message?: string) =>
  new RequestError(
    {
      code: getInlineHookDeniedErrorCode(key),
      status,
    },
    message && { message }
  );

const tryParseInlineHookResponseError = async (error: unknown) => {
  if (!(error instanceof ResponseError)) {
    return;
  }

  const responseBody: unknown = await error.response.json();
  const accessDeniedError = isAccessDeniedError(responseBody);

  if (accessDeniedError) {
    return {
      message: responseBody.message,
      error: responseBody,
    };
  }

  return inlineHookResponseErrorGuard.safeParse(responseBody).data;
};

export const getInlineHookExecutionErrorPolicyDecision = async ({
  key,
  error,
  onExecutionError = defaultInlineHookExecutionErrorPolicy,
}: InlineHookExecutionErrorHandlingData): Promise<InlineHookExecutionErrorPolicyDecision> => {
  const responseError = await tryParseInlineHookResponseError(error);
  const accessDeniedError = isAccessDeniedError(error)
    ? error
    : isAccessDeniedError(responseError?.error)
      ? responseError.error
      : undefined;

  if (accessDeniedError) {
    return {
      action: 'throw',
      error: createInlineHookDeniedError(key, 403, accessDeniedError.message),
    };
  }

  if (onExecutionError === 'allow') {
    return key === LogtoInlineHookKey.PostFirstFactorVerification
      ? { action: 'rejectInvalidCredentials' }
      : { action: 'continue' };
  }

  return {
    action: 'throw',
    error: createInlineHookDeniedError(
      key,
      403,
      error instanceof Error ? error.message : responseError?.message
    ),
  };
};

const handleInlineHookExecutionError = async (data: InlineHookExecutionErrorHandlingData) => {
  const decision = await getInlineHookExecutionErrorPolicyDecision(data);

  if (decision.action === 'throw') {
    throw decision.error;
  }

  return decision.action === 'rejectInvalidCredentials' ? decision : undefined;
};

export class InlineHookLibrary {
  static async runScriptInLocalVm<Event>({
    script,
    event,
    environmentVariables,
  }: InlineHookRunnerData<Event>): Promise<unknown> {
    try {
      const payload: InlineHookScriptPayload<Event> = {
        event,
        environmentVariables,
        api: apiContext,
      };

      return await runScriptFunctionInLocalVm(script, inlineHookFunctionName, payload);
    } catch (error: unknown) {
      if (error instanceof LocalVmError) {
        throw error;
      }

      if (error instanceof LocalVmTimeoutError) {
        throw new LocalVmError(buildLocalVmErrorBody(error), 504);
      }

      if (error instanceof ZodError) {
        throw new LocalVmError(
          {
            message: 'Invalid input',
            errors: error.errors,
          },
          400
        );
      }

      throw new LocalVmError(
        buildLocalVmErrorBody(error),
        error instanceof SyntaxError || error instanceof TypeError ? 422 : 500
      );
    }
  }

  constructor(private readonly logtoConfigs: LogtoConfigLibrary) {}

  async runHook<Event>({
    key,
    event,
  }: {
    key: LogtoInlineHookKey;
    event: Event;
  }): Promise<unknown> {
    if (!EnvSet.values.isDevFeaturesEnabled) {
      return;
    }

    const inlineHook = await this.logtoConfigs.getInlineHook(key);

    if (!inlineHook?.enabled) {
      return;
    }

    try {
      return await InlineHookLibrary.runScriptInLocalVm({
        script: inlineHook.script,
        event,
        environmentVariables: inlineHook.environmentVariables,
      });
    } catch (error: unknown) {
      return handleInlineHookExecutionError({
        key,
        error,
        onExecutionError: inlineHook.onExecutionError,
      });
    }
  }
}
