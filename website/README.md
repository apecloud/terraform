# Terraform Documentation

This directory contains the portions of [the Terraform website](https://www.terraform.io/) that pertain to the core functionality, excluding providers and the overall configuration.

The files in this directory are intended to be used in conjunction with
[the `terraform-website` repository](https://github.com/hashicorp/terraform-website), which brings all of the
different documentation sources together and contains the scripts for testing and building the site as
a whole.

## Suggesting Changes

You can [submit an issue](https://github.com/hashicorp/terraform/issues/new/choose) with documentation requests or submit a pull request with suggested changes.

Click **Edit this page** at the bottom of any Terraform website page to go directly to the associated markdown file in GitHub.

## Modifying Sidebar Navigation

Updates to the sidebar navigation of Terraform docs need to be made in the [`terraform-website`](https://github.com/hashicorp/terraform-website/) repository (preferably in a PR also updating the submodule commit). You can read more about how to make modifications to the navigation in the [README for `terraform-website`](https://github.com/hashicorp/terraform-website#editing-navigation-sidebars).

## Adding Redirects

You must add a redirect when you move, rename, or delete documentation pages. Refer to https://github.com/hashicorp/terraform-website#redirects for details.

## Previewing Changes

You should preview all of your changes locally before creating a pull request. The build includes content from this repository and the [`terraform-website`](https://github.com/hashicorp/terraform-website/) repository, allowing you to preview the entire Terraform documentation site.

**Set Up Local Environment**

1. [Install Docker](https://docs.docker.com/get-docker/).
2. Create a `~/go` directory manually or by [installing Go](https://golang.org/doc/install).
3. Open terminal and set `GOPATH` as an environment variable:

   Bash: `export $GOPATH=~/go`(bash)

   Zsh: `echo -n 'export GOPATH=~/go' >> ~/.zshrc`

4. Restart your terminal or command line session.

**Launch Site Locally**

1. Navigate into your local `terraform` top-level directory and run `make website`.
1. Open `http://localhost:3000` in your web browser. While the preview is running, you can edit pages and Next.js will automatically rebuild them.
1. When you're done with the preview, press `ctrl-C` in your terminal to stop the server.


## Deploying Changes
The website generates versioned documentation by pointing to the HEAD of the release branch for that version. For example, the `v1.2.x` documentation on the website points to the HEAD of the `v1.2` release branch in the `terraform` repository. 

Merging a PR to `main` queues up documentation changes for the next minor product release. To update the latest documentation, you must also backport your changes to one or more release branches. Changes that you push to a release branch become live on the site within one hour.

For example, if Terraform is on v1.2.x:
- Merge to `main`: Documentation for v1.3 features.
- Merge to `main` and backport to `v1.2` release branch: Typo fixes, page restructures, documentation to support v1.2 patch releases, etc.

### Backporting

**Important:** Editing old versions (not latest) should be rare. We backport to old versions when there is an egregious error. Egregious errors include inaccuracies that could cause security vulnerabilities or extreme inconvenience for users. 

Backporting involves cherry-picking commits to one or more release branches within a docs repository. For example, if Terraform is currently on v1.2 and you need to add a security warning to the v1.1 documentation, you can backport (cherry-pick) commits to the v1.1 branch by labeling the PR with a backport label (e.g., 1.2-backport) associated with the release branch for the target version. 

When you merge a pull request with one or more backport labels, GitHub Actions opens a backport PR to cherry-pick your changes to the associated release branches. Someone needs to manually merge the backport PR to finish backporting the changes.  

If the changes in the backport pull request are effectively equivalent to the original, you can review and merge your own backport pull request without waiting for another review. You can make minor adjustments to resolve merge conflicts, but you should not merge a backport PR that contains major content or functionality changes from the original, approved pull request.

If you are not sure whether it is okay to merge a backport pull request, post a comment on the original pull request to discuss with the team.
