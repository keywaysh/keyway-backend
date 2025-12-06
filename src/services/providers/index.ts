/**
 * Provider Registry
 * Import this file to register all available providers
 */

export * from './base.provider';
export * from './vercel.provider';
export * from './railway.provider';

// Import providers to register them
import './vercel.provider';
import './railway.provider';
