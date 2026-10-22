// Firebase's browser configuration contains public project identifiers, not server credentials.
// Access is constrained by Google API restrictions, authorized domains, MFA, and backend token verification.
export const firebaseConfig = Object.freeze({
  apiKey: 'AIzaSyBB00drV0Itdx5RKjMC-e6gPCPSoFNakDM',
  authDomain: 'uptier-502917.firebaseapp.com',
  projectId: 'uptier-502917',
  storageBucket: 'uptier-502917.firebasestorage.app',
  messagingSenderId: '1076418370349',
  appId: '1:1076418370349:web:68ec4474345f390ab8d1a4'
});

const productionBackendOrigin = 'https://uptier-plaid-backend-1076418370349.us-central1.run.app';

export function backendOriginsForPortalLocation(location = globalThis.location) {
  const origins = [productionBackendOrigin];
  const isLocalPortal = location?.protocol === 'http:'
    && (location.hostname === '127.0.0.1' || location.hostname === 'localhost');
  if (isLocalPortal) origins.push('http://127.0.0.1:8788');
  return Object.freeze(origins);
}

// A hosted production portal may exchange identity only with the production backend.
// The loopback backend is exposed solely when this page itself is served from loopback.
export const allowedBackendOrigins = backendOriginsForPortalLocation();
