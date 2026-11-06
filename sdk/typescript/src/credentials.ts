import * as api from './operations/index.js';
import {CredentialInjectProvider, CredentialStorage, type CredentialInjectResponse} from './models/index.js';
import type {CallOptions, Transport} from './transport.js';

/** Explicit host material; responses contain only opaque references. */
export class Credentials {
  constructor(private readonly transport: Transport) {}

  /** Provider `http` requires `binding`, a host-declared `[credential_bindings.<id>]` id. */
  async inject(provider: `${CredentialInjectProvider}`, value: string,
    options: CallOptions & {storage?: `${CredentialStorage}`, binding?: string} = {}): Promise<CredentialInjectResponse> {
    if (typeof value !== 'string' || !value) throw new TypeError('Credential value must be a nonempty string');
    const {binding} = options;
    if ((provider === 'http') !== (typeof binding === 'string' && binding.length > 0)) {
      throw new TypeError('A credential binding is required with, and only with, provider http');
    }
    if (!Object.values(CredentialInjectProvider).includes(provider as CredentialInjectProvider)) {
      throw new TypeError('Invalid credential provider');
    }
    const storage = options.storage ?? CredentialStorage.FILE;
    if (!Object.values(CredentialStorage).includes(storage as CredentialStorage)) throw new TypeError('Invalid credential storage');
    return api.injectCredential(this.transport, {body: {
      provider: provider as CredentialInjectProvider, value, storage: storage as CredentialStorage,
      ...(binding === undefined ? {} : {binding}),
    }}, options);
  }
}
