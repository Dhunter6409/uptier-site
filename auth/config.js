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

export const allowedBackendOrigins = Object.freeze([
  // Development-only loopback origin. Production will add its HTTPS API origin before launch.
  'http://127.0.0.1:8788'
]);
