import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'path';
import type { IEncryptionService, EncryptedData } from './encryption';

interface CryptoClient {
  Encrypt: (
    request: { plaintext: Buffer; version: number },
    callback: (err: Error | null, response: EncryptResponse) => void
  ) => void;
  Decrypt: (
    request: { ciphertext: Buffer; iv: Buffer; authTag: Buffer; version: number },
    callback: (err: Error | null, response: DecryptResponse) => void
  ) => void;
  HealthCheck: (
    request: Record<string, never>,
    callback: (err: Error | null, response: HealthResponse) => void
  ) => void;
}

interface EncryptResponse {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
  version: number;
}

interface DecryptResponse {
  plaintext: Buffer;
}

interface HealthResponse {
  healthy: boolean;
  version: string;
}

class CryptoServiceError extends Error {
  constructor(
    message: string,
    public readonly operation: 'encrypt' | 'decrypt' | 'healthcheck',
    public readonly serviceUrl: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'CryptoServiceError';
  }
}

function formatGrpcError(err: Error & { code?: number; details?: string }, serviceUrl: string, operation: string): CryptoServiceError {
  const grpcCode = err.code;
  const details = err.details || err.message;

  let userMessage: string;

  switch (grpcCode) {
    case 14: // UNAVAILABLE
      userMessage = `Crypto service unavailable at ${serviceUrl}. Check that the service is running and accessible. Details: ${details}`;
      break;
    case 4: // DEADLINE_EXCEEDED
      userMessage = `Crypto service timeout at ${serviceUrl}. The service is not responding in time.`;
      break;
    case 2: // UNKNOWN
      userMessage = `Crypto service error at ${serviceUrl}. Unknown error: ${details}`;
      break;
    case 13: // INTERNAL
      userMessage = `Crypto service internal error at ${serviceUrl}. Details: ${details}`;
      break;
    default:
      userMessage = `Crypto service error (code ${grpcCode}) at ${serviceUrl}: ${details}`;
  }

  return new CryptoServiceError(
    userMessage,
    operation as 'encrypt' | 'decrypt' | 'healthcheck',
    serviceUrl,
    err
  );
}

export class RemoteEncryptionService implements IEncryptionService {
  private client: CryptoClient;
  private serviceUrl: string;

  constructor(address: string = 'localhost:50051') {
    this.serviceUrl = address;
    const protoPath = path.join(__dirname, '../../proto/crypto.proto');
    const packageDef = protoLoader.loadSync(protoPath, {
      keepCase: false,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
    });
    const proto = grpc.loadPackageDefinition(packageDef) as unknown as {
      keyway: {
        crypto: {
          CryptoService: new (
            address: string,
            credentials: grpc.ChannelCredentials
          ) => CryptoClient;
        };
      };
    };
    this.client = new proto.keyway.crypto.CryptoService(
      address,
      grpc.credentials.createInsecure()
    );
  }

  async encrypt(content: string): Promise<EncryptedData> {
    return new Promise((resolve, reject) => {
      this.client.Encrypt(
        { plaintext: Buffer.from(content, 'utf-8'), version: 1 },
        (err, response) => {
          if (err) {
            return reject(formatGrpcError(err as Error & { code?: number; details?: string }, this.serviceUrl, 'encrypt'));
          }
          resolve({
            encryptedContent: Buffer.from(response.ciphertext).toString('hex'),
            iv: Buffer.from(response.iv).toString('hex'),
            authTag: Buffer.from(response.authTag).toString('hex'),
          });
        }
      );
    });
  }

  async decrypt(data: EncryptedData): Promise<string> {
    return new Promise((resolve, reject) => {
      this.client.Decrypt(
        {
          ciphertext: Buffer.from(data.encryptedContent, 'hex'),
          iv: Buffer.from(data.iv, 'hex'),
          authTag: Buffer.from(data.authTag, 'hex'),
          version: 1,
        },
        (err, response) => {
          if (err) {
            return reject(formatGrpcError(err as Error & { code?: number; details?: string }, this.serviceUrl, 'decrypt'));
          }
          resolve(Buffer.from(response.plaintext).toString('utf-8'));
        }
      );
    });
  }

  async healthCheck(): Promise<{ healthy: boolean; version: string }> {
    return new Promise((resolve, reject) => {
      this.client.HealthCheck({}, (err, response) => {
        if (err) {
          return reject(formatGrpcError(err as Error & { code?: number; details?: string }, this.serviceUrl, 'healthcheck'));
        }
        resolve({ healthy: response.healthy, version: response.version });
      });
    });
  }
}

/**
 * Check crypto service connectivity
 * Throws CryptoServiceError with detailed message if not accessible
 */
export async function checkCryptoService(serviceUrl: string): Promise<{ healthy: boolean; version: string }> {
  const service = new RemoteEncryptionService(serviceUrl);
  return service.healthCheck();
}
