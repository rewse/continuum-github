# Setup

This guide connects AWS Security Agent and AWS Continuum in one AWS account to a private GitHub repository that holds the finding issues and runs the workflows. The examples use the owner `example-org`, the report repository `example-org/security-findings`, the account `111122223333`, and the Region `us-east-1`; replace them with your own.

Most steps write to AWS or GitHub, so read what a step changes before running it. You need the AWS CLI 2.37.12 or later, `uv`, and `gh`. Run the commands from the root of a checkout of your report repository. Steps 3 and 4 create IAM resources, so they need credentials that may do that.

The `continuum-github setup` commands run from a release of this repository through `uvx`. Set `SHA` to the commit SHA of the release you use:

```sh
SHA=<release commit SHA>
export AWS_REGION=us-east-1
```

`continuum-github setup` reads the Region from `AWS_REGION` and uses `us-east-1` when it is unset. It ignores the Region of your AWS CLI profile, so export `AWS_REGION` with the Region of your Agent Space in the shell that runs steps 5 to 7.

## 1. Write the targets file

Copy [examples/targets.toml](../examples/targets.toml) to `targets.toml` in your report repository and list your repositories and sites. `owner` is the GitHub owner of the scanned repositories, and each repository says whether it is private. Private repositories get code-vuln scans and PR review comments, and public ones get a code review. Each site names the title of its pentest and the repository whose label its issues get.

## 2. Install the Security Agent GitHub App

The pentests, the code reviews, and the PR review use the Security Agent GitHub integration. If AWS Security Agent is not yet enabled in the account, open its console in your Region and complete the initial setup first.

1. In the AWS Security Agent console, open Settings, then Integrations, and add a GitHub integration.
2. Choose your account or organization as the connection type and continue to GitHub.
3. Install the AWS Security Agent GitHub App with Only select repositories, and select the repositories in `targets.toml`.
4. Finish the redirect back to the console. Skip any prompt to connect repositories or enable code review; the stack and steps 6 and 7 do that.

Read the integration ID:

```sh
aws securityagent list-integrations --region us-east-1 \
  --query "integrationSummaries[?provider=='GITHUB'].[integrationId, displayName]" \
  --output table | cat
```

## 3. Prepare the AWS side

The tool does not create the Agent Space, the pentests, their schedules, or AWS Config recording. Prepare them yourself, starting from the example templates. Copy [examples/infra/security-agent.yaml](../examples/infra/security-agent.yaml) and [examples/infra/github-actions-role.yaml](../examples/infra/github-actions-role.yaml), which step 4 uses, to `infra/` in your report repository. Take them from a checkout of the release whose SHA you set above, such as a clone of its tag outside the report repository:

```sh
git clone --depth 1 --branch <release tag> https://github.com/rewse/continuum-github.git <path to continuum-github>
git -C <path to continuum-github> rev-parse HEAD  # should print $SHA
mkdir -p infra
cp <path to continuum-github>/examples/infra/security-agent.yaml \
  <path to continuum-github>/examples/infra/github-actions-role.yaml infra/
```

The copy of `security-agent.yaml` creates an Agent Space with two connected repositories, the Security Agent service role, one target domain, one pentest with a weekly EventBridge Scheduler schedule, AWS Config recording with its bucket, and the role that the code-vuln collector uses to read AWS Config. Its comments describe how to add sign-in for a site and how to leave out risk types whose probes could change data or availability.

In `infra/security-agent.yaml`, change the repositories, target domains, pentests, and schedules to match `targets.toml`. The title of each pentest must equal the `pentest` of its site. The AWS Config recorder uses the service-linked role `AWSServiceRoleForConfig`; create it first with `aws iam create-service-linked-role --aws-service-name config.amazonaws.com` if it does not exist. If AWS Config already records in the Region, remove the recorder, the delivery channel, and the bucket from the template.

A pentest needs verified target domains, so deploy the template twice. The first deployment leaves out the pentests:

```sh
aws cloudformation deploy --region us-east-1 \
  --stack-name security-agent \
  --template-file infra/security-agent.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides GitHubIntegrationId=<integration ID> \
    GitHubOwner=example-org TargetDomainsVerified=false
```

Verify each target domain in the console's Penetration test tab of the Agent Space, through its DNS TXT record. Read the `providerResourceId` of the repository each pentest reads:

```sh
aws securityagent list-integrated-resources --region us-east-1 \
  --agent-space-id <AgentSpaceId> --integration-id <integration ID> \
  --query "integratedResourceSummaries[].resource.githubRepository.[name, providerResourceId]" \
  --output table | cat
```

Once every domain shows `VERIFIED`, deploy again with `TargetDomainsVerified=true` and `WebResourceId=<providerResourceId>`. A stack update can reset the PR review capabilities of the connected repositories, so run step 7 again after every deployment.

The stack outputs `AgentSpaceId`, `CollectorAccessRoleArn`, and `ServiceRoleArn`, which the next steps use:

```sh
aws cloudformation describe-stacks --region us-east-1 --stack-name security-agent \
  --query "Stacks[0].Outputs" --output table | cat
```

## 4. Create the GitHub Actions role

`infra/github-actions-role.yaml`, copied in step 3, creates the GitHub OIDC provider and a role with the permissions the actions need: read access to the Agent Space's pentests, code reviews, and findings, permission to start code review jobs and pentest revalidations, and read access to the Continuum code-vuln findings. The role trusts only workflows on the `main` branch of the report repository.

The trust policy uses GitHub's immutable OIDC subject, which embeds the numeric IDs of the owner and the repository, so a renamed or recreated repository cannot assume the role. GitHub uses this format for repositories created, renamed, or transferred after July 15, 2026. Older repositories keep the name-based format until someone opts in, and `gh api repos/<owner>/<repo>/actions/oidc/customization/sub` shows the repository's setting as `use_immutable_subject`. Read the IDs:

```sh
gh api repos/example-org/security-findings --jq '.owner.id, .id'
```

Then deploy:

```sh
aws cloudformation deploy --region us-east-1 \
  --stack-name continuum-github \
  --template-file infra/github-actions-role.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides AgentSpaceId=<AgentSpaceId> \
    GitHubOwner=example-org GitHubOwnerId=<owner ID> \
    GitHubRepository=security-findings GitHubRepositoryId=<repository ID>
```

An account holds only one OIDC provider for `token.actions.githubusercontent.com`. If one already exists, remove `GitHubOidcProvider` from `infra/github-actions-role.yaml` and use the existing provider's ARN in the trust policy. If your repository's tokens use the older subject format, `repo:<owner>/<repository>:ref:refs/heads/main`, change the condition to match. The stack output `GitHubActionsRoleArn` is the role's ARN.

## 5. Create the code-vuln environments

code-vuln uses its own GitHub integration, which you authorize in the browser once. Only private repositories use it, because Continuum rejects public ones.

1. In the AWS Continuum console, add a GitHub integration for your account or organization.
2. Authorize it on GitHub and select the private repositories in `targets.toml`.
3. Read its ID:

```sh
aws continuum list-integrations --region us-east-1 \
  --query "items[?integrationType=='GITHUB'].[integrationId, name]" --output table | cat
```

Then create the environments:

```sh
uvx --from "git+https://github.com/rewse/continuum-github@$SHA" continuum-github setup code-vuln \
  --integration-id <Continuum integration ID> \
  --collector-repository api \
  --collector-role-arn <CollectorAccessRoleArn>
```

The command creates or updates one environment per private repository, named `<owner>-<repository>`, with a scan frequency of `P7D` and patch creation on. It skips the public repositories, which step 6 covers.

`--collector-repository` is optional. With it, the command also creates an AWS collector, which reads AWS Config in the Region, and attaches it to the environment of that private repository so that Continuum can reassess its findings against the deployed resources. Name the repository whose code deploys to this account and Region. `--collector-role-arn`, the stack output `CollectorAccessRoleArn`, is required together with it. Without `--collector-repository`, the command creates no collector. It prints `environments=<count> collector=<collector ARN>`, or `collector=none` without a collector, and it is safe to rerun.

## 6. Create the code reviews

```sh
AGENT_SPACE_ID=<AgentSpaceId> uvx --from "git+https://github.com/rewse/continuum-github@$SHA" \
  continuum-github setup code-review \
  --integration-id <Security Agent integration ID> \
  --service-role-arn <ServiceRoleArn>
```

The command creates one code review per public repository in the Agent Space, titled `weekly-<repository>`, with the Security Agent integration ID from step 2 and the service role from step 3. Each review uses `validationMode` `SIMULATED` and `codeRemediationStrategy` `DISABLED`, so it proposes no fixes. It prints `code_reviews=<count> created=<count>`. It skips a repository whose code review already exists, matched by title. `ListCodeReviews` can take a few minutes to show a new review, so wait a few minutes before a rerun, or the rerun creates duplicates. The command only creates the reviews; the `sync` action starts their jobs once a week.

## 7. Configure the PR review

```sh
AGENT_SPACE_ID=<AgentSpaceId> uvx --from "git+https://github.com/rewse/continuum-github@$SHA" \
  continuum-github setup pr-review \
  --integration-id <Security Agent integration ID>
```

The command sends all repositories in one `UpdateIntegratedResources` call. It turns PR comments on and remediation pull requests off for the private repositories. It sets no trigger filter, so Security Agent reviews every non-draft pull request, including Dependabot's. Security Agent rejects PR comments on public repositories, so those stay connected with comments and remediation off. PR review files no issues. Rerun it after every deployment of the stack from step 3.

## 8. Create the GitHub labels

```sh
GITHUB_TOKEN="$(gh auth token)" REPORT_REPOSITORY=example-org/security-findings \
  uvx --from "git+https://github.com/rewse/continuum-github@$SHA" continuum-github setup labels
```

The command creates the state, severity, source, `urgent`, `weekly-report`, `repo:<name>`, and `site:<domain>` labels in the report repository, skipping the ones that exist. Create them before the first sync, because GitHub can drop a label that the token is not allowed to create. Rerun it after adding a repository or a site to `targets.toml`.

## 9. Register the variables

```sh
gh variable set AGENT_SPACE_ID --repo example-org/security-findings --body <AgentSpaceId>
gh variable set AWS_ROLE_ARN --repo example-org/security-findings --body <GitHubActionsRoleArn>
gh variable set MENTION --repo example-org/security-findings --body @example-user
```

`MENTION` is optional. When set, urgent issues mention it; when unset or empty, they mention no one.

If you upgrade from v0.1, the actions no longer take the `kiro-api-key` input. Remove it from the `with:` of both workflows, and delete the secret:

```sh
gh secret delete KIRO_API_KEY --repo example-org/security-findings
```

If you upgrade from v0.2 or earlier, the model now writes in `en_US` unless you choose a language, and the visual report file is `report.html` instead of `report.ja.html`. To keep the visual report in Japanese, pass `language: ${{ vars.LANGUAGE }}` to both actions, as the example workflows do, and set the variable:

```sh
gh variable set LANGUAGE --repo example-org/security-findings --body ja_JP
```

The issue sections and the severity summaries then switch to Japanese as well.

## 10. Add the workflows

Copy [examples/workflows/sync.yml](../examples/workflows/sync.yml) and [examples/workflows/report.yml](../examples/workflows/report.yml) to `.github/workflows/` in your report repository. They reference the actions with a placeholder SHA of zeros and the comment `# vX.Y.Z`. Replace both with the commit SHA and version of the release you use:

```yaml
uses: rewse/continuum-github/sync@<release commit SHA>  # v1.2.3
```

Add a Dependabot configuration for the `github-actions` ecosystem, and Dependabot then keeps the SHA and its version comment current. Adjust the schedules if you like. `sync.yml` runs every two hours, and `report.yml` runs every Friday at 21:35 UTC. The role trusts only `main`, so both jobs run only there. If the Agent Space is not in `us-east-1`, set `aws-region` in both the AWS credentials step and the action to the Region you exported as `AWS_REGION`. Keep the default `github-token` and `report-repository` inputs, because sync recognizes only the issues that `github-actions[bot]` opened in the report repository.

Commit `targets.toml` and the workflows to `main`, then run each workflow once by hand:

```sh
gh workflow run sync.yml --repo example-org/security-findings
gh workflow run report.yml --repo example-org/security-findings
```

Both are safe to rerun. They share a concurrency group, so a run waits until the other workflow finishes. After this, the schedules in AWS and the two workflows run on their own. [README.md](../README.md) describes the issues they file and how to handle them.

## 11. Turn on the model (optional)

Without a model, the issues and the weekly report hold only what the scans returned. To have a Bedrock model add sections to each issue, summarize each severity in the report, and write the visual report:

1. Make the model available in your account. For an Anthropic model, submit the use case form once per account, then have an administrator invoke the model once in the Bedrock console. That first call enables the model for the account, so the GitHub Actions role needs no `aws-marketplace` permissions.
2. Make sure the GitHub Actions role allows `bedrock:InvokeModel`, as the role in [examples/infra/github-actions-role.yaml](../examples/infra/github-actions-role.yaml) does.
3. Set the model ID:

   ```sh
   gh variable set BEDROCK_MODEL_ID --repo example-org/security-findings --body global.anthropic.claude-sonnet-5-5
   ```

4. Optionally, choose the language the model writes in. The default is `en_US`:

   ```sh
   gh variable set LANGUAGE --repo example-org/security-findings --body ja_JP
   ```

5. Raise the repository's artifact retention. The report action keeps the visual report for 400 days, but GitHub cuts an artifact's retention to the repository's limit, which is 90 days by default, and the links in older weekly reports stop working after that:

   ```sh
   gh api -X PUT repos/example-org/security-findings/actions/permissions/artifact-and-log-retention -F days=400
   ```

The example workflows pass `BEDROCK_MODEL_ID` and `LANGUAGE` to the actions. The value of `LANGUAGE` is a locale such as `ja`, `ja_JP`, or `zh_TW`; any other form fails the job before the model is called. `global.anthropic.claude-sonnet-5-5` is the recommended model. The page source of the visual report needs a long output, so a model with a small output limit fails on it. The next sync adds the sections to open issues that lack them.

When a model call fails after its retries, the job log shows a line such as `model_failed purpose=page reason=ValidationException`, with the error code and nothing from the findings. The issue or the report then ends with a note that names the part the model could not write.

## Changing the targets

When `targets.toml` changes, update the connected repositories, target domains, pentests, and schedules in your AWS stack to match. Add a new repository to the Security Agent GitHub App and, for a private repository, to the Continuum integration. Then deploy the stack and run steps 5 to 8 again.
