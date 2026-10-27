# Firebase Hosting release runbook

This repository prepares the reviewed public UpTier site for Firebase Hosting at `uptier-502917`. The account portal's production URL is:

`https://uptier-502917.web.app/auth/`

The build is intentionally allowlisted. `scripts/hosting-files.mjs` names every file that may enter `.firebase-site`; repository documentation, workflows, tests, and credentials cannot be copied by a recursive repository publish. A new public page or asset must be reviewed and added to that manifest.

## Boundaries

- These files do not change the desktop or iOS app's account-portal URL, Firebase Authentication authorized domains, Google Identity settings, backend CORS, DNS, or traffic.
- Never enter account credentials on a preview-channel URL. Firebase Authentication preview domains are not the production authorized domain, and preview verification here is static and read-only.
- Do not store Firebase login state, service-account JSON, tokens, or CI secrets in this repository.
- The first Firebase Hosting release has no earlier Firebase release to restore. Keep the current app portal URL unchanged until the new live URL passes verification and the separate app/backend/Identity change is approved.

## Build and verify one exact commit

Use a clean worktree on the exact reviewed commit. The commands below are PowerShell:

```powershell
$expected = (git rev-parse HEAD).Trim()
if ($expected -notmatch '^[0-9a-f]{40}$') { throw 'A full commit hash is required.' }
if (git status --porcelain=v1 --untracked-files=all) { throw 'The release worktree is not clean.' }

node --check auth/app.js
node --check auth/sync-key-flow.mjs
node --check scripts/stage-hosting.mjs
node --check scripts/verify-hosting-build.mjs
node --check scripts/verify-hosting-remote.mjs
node --check scripts/read-hosting-channel-version.mjs
node --test scripts/account-flow.test.mjs scripts/hosting-build.test.mjs scripts/sync-key-flow.test.mjs
node scripts/check-site.mjs
node scripts/stage-hosting.mjs
$buildEvidence = node scripts/verify-hosting-build.mjs --expected-source-sha $expected | ConvertFrom-Json
```

The last command fails unless the checked-out commit matches `$expected`, the worktree is clean, the target project/site and headers are exact, the staged path set is exact, and every staged byte matches its source byte. Save `$buildEvidence` with the release record: `contentAggregateSha256` identifies the 24 deployable source files, `stagedArtifactAggregateSha256` also covers the generated `.nojekyll` control file used by GitHub Pages, and `releaseInputAggregateSha256` additionally covers the exact `firebase.json` and `.firebaserc` release configuration.

For pre-commit review only, `node scripts/verify-hosting-build.mjs --allow-dirty` exercises the content checks without claiming an exact releasable commit.

## Preview without credentials

Firebase CLI authentication is an operator prerequisite and is handled outside this repository. Confirm the CLI is on the intended Google account and project before any write:

```powershell
firebase projects:list
$channel = "auth-$($expected.Substring(0, 8))-$($buildEvidence.releaseInputAggregateSha256.Substring(0, 8))"
firebase hosting:channel:deploy $channel --project uptier-502917 --expires 1d --no-authorized-domains
$channelState = node scripts/read-hosting-channel-version.mjs --channel $channel | ConvertFrom-Json
$versionId = $channelState.versionId
```

`--no-authorized-domains` is required: Firebase CLI otherwise attempts to add the temporary preview hostname to Firebase Authentication. Record the preview origin printed by the CLI. The channel-state command resolves the preview release to one immutable Firebase Hosting version. Verify every deployed file and the account-page response headers without signing in, while independently checking that the channel points to that same version before and after the byte comparison:

```powershell
node scripts/verify-hosting-remote.mjs --origin https://PREVIEW_ORIGIN_FROM_FIREBASE --expected-channel $channel --expected-source-sha $expected --expected-version-id $versionId
```

The remote verifier rejects a dirty or different source tree, downloads only public GET resources, compares each response SHA-256 to `.firebase-site`, validates the production account-page cache and security headers, checks the immutable Firebase version before and after the download, and reports the source commit plus content, staged-artifact, and release-input hashes. Do not proceed if any source, version, byte, header, or configuration hash differs. Save this preview evidence with `$channelState` and `$buildEvidence`.

## Promote the verified version to live

Promotion is a separate production approval. Clone the verified immutable version ID, never the mutable channel name. Firebase documents `SITE_ID:@VERSION_ID` as the exact-version clone form; this prevents a later preview redeploy from changing what reaches live:

```powershell
firebase hosting:clone "uptier-502917:@$versionId" "uptier-502917:live" --project uptier-502917
node scripts/verify-hosting-remote.mjs --origin https://uptier-502917.web.app --live --expected-source-sha $expected --expected-version-id $versionId
```

Confirm that `https://uptier-502917.web.app/auth/` returns the reviewed portal and the remote verifier reports the same commit, immutable version, release-input hash, content aggregate, and all 24 source files. This still does not authorize an app release or any app/backend/Identity configuration change.

## Canonical and client cutover order

The first Hosting/provenance commit deliberately leaves the public canonical URLs, sitemap, and GitHub Pages metadata on the existing GitHub origin. After the first exact Firebase version is live and verified, prepare the canonical URL change as a separate commit. Build that clean commit, deploy it to a new preview channel, verify and promote its exact `@VERSION_ID`, and verify live again **before** merging or publishing that canonical switch through GitHub Pages. Only after the production Firebase portal is live and verified may the separately reviewed app URL, backend auth-portal/CORS, and authorized-domain cutover proceed.

## Rollback

For an existing Firebase release, the fastest rollback is Firebase Console **Hosting > Release history > Roll back** to the recorded prior verified release. Before rerunning the static remote verifier, check out that prior release's exact source commit in a clean worktree and rebuild its `.firebase-site`; the verifier intentionally rejects live bytes that differ from the locally staged artifact. Record the resulting release identifier and the rebuilt prior commit's hashes.

The deterministic command-line alternative is to rebuild a known-good prior site commit in a separate clean worktree, run every local verification above with that commit's full SHA, deploy it to a new short-lived preview channel, verify the remote hashes and immutable version ID, and clone that exact `SITE_ID:@VERSION_ID` to `uptier-502917:live`. Do not clone a mutable channel name, reuse an unverified local directory, or rebuild from a dirty checkout.

For the first-ever Firebase release there is no prior Firebase artifact. The rollback boundary is therefore to leave (or restore in its separately reviewed app change) the prior account-portal URL and take the new Firebase endpoint out of use. Do not remove the current GitHub Pages site as part of this migration.
