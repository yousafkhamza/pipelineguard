// Sample workflows for the live demo and the tests. All credentials are fake.
export const SAMPLES = [
  {
    key: "preview",
    label: "Fork PR preview deploy",
    file: "preview.yml",
    text: `name: preview
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - name: Install
        run: curl -fsSL https://get.pnpm.io/install.sh | sh -
      - name: Announce
        run: echo "Building \${{ github.event.pull_request.title }}"
      - uses: some-org/s3-deploy@main
        with:
          bucket: previews
      - name: Log in to registry
        run: echo "\${{ secrets.REGISTRY_TOKEN }}"
`,
  },
  {
    key: "triage",
    label: "Issue triage bot",
    file: "triage.yml",
    text: `name: triage
on:
  issues:
    types: [opened]
  issue_comment:
    types: [created]

permissions: write-all

jobs:
  label:
    runs-on: ubuntu-latest
    if: contains(github.event.comment.body, '/label')
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const title = "\${{ github.event.issue.title }}";
            await github.rest.issues.addLabels({ ...context.repo, issue_number: context.issue.number, labels: [title.split(':')[0]] });
      - run: echo "Labelled by \${{ github.event.comment.user.login }}"
`,
  },
  {
    key: "release",
    label: "Release with a leaked key",
    file: "release.yml",
    text: `name: release
on:
  push:
    tags: ["v*"]

env:
  AWS_ACCESS_KEY_ID: AKIAQX3EXAMPLE7KPL2M
  ACTIONS_ALLOW_UNSECURE_COMMANDS: true

jobs:
  publish:
    runs-on: ubuntu-latest
    container:
      image: node:latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm ci && npm run build
      - run: aws s3 sync dist/ s3://downloads.example.com/\${{ github.ref_name }}/

  notify:
    needs: publish
    uses: example-org/shared/.github/workflows/notify.yml@v1
    secrets: inherit
`,
  },
  {
    key: "legacy",
    label: "Legacy deploy pipeline",
    file: "deploy.yml",
    text: `name: deploy
on:
  workflow_dispatch:
    inputs:
      environment:
        default: staging
  workflow_run:
    workflows: [ci]
    types: [completed]

permissions:
  contents: read
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-20.04
    timeout-minutes: 30
    if: \${{ github.actor }} == 'release-bot'
    steps:
      - uses: actions/checkout@v4
      - uses: actons/setup-node@v4
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: npm-\${{ hashFiles('package-lock.json') }}
      - run: npm install
      - id: meta
        run: echo "::set-output name=tag::\$(git describe --tags)"
      - uses: tj-actions/changed-files@v45
      - name: Audit
        run: npm audit --audit-level=high
        continue-on-error: true
      - name: Ship
        env:
          API_TOKEN: \${{ secrets.API_TOKEN }}
        run: |
          set -x
          curl -k https://artifacts.internal/cli.tgz -o cli.tgz
          ./ship.sh \${{ inputs.environment }} \${{ steps.meta.outputs.tag }}
          gh release create v1 --repo x/y --token \${{ github.token }}
          docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock scanner
      - uses: docker/login-action@v3
        with:
          username: deployer
          password: hunter2
      - uses: actions/upload-artifact@v4
        with:
          path: .
      - uses: actions/create-release@v1
`,
  },
  {
    key: "hardened",
    label: "Hardened CI (clean)",
    file: "ci.yml",
    text: `name: ci
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af # v4.1.0
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - name: Test
        env:
          PR_TITLE: \${{ github.event.pull_request.title }}
        run: |
          echo "Testing: $PR_TITLE"
          npm test
`,
  },
];
