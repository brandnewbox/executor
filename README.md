# Executor

Brand New Box build of [Executor](https://executor.sh) with the [1Password plugin](https://github.com/UsefulSoftwareCo/executor/tree/main/packages/plugins/onepassword) enabled.

```text
registry.digitalocean.com/brandnewbox/executor
```

The image otherwise follows Executor's upstream self-hosted build. Upstream source is pinned by `EXECUTOR_VERSION` in the `Dockerfile`.

## Release

Create a tag using the upstream version plus a BNB build number:

```sh
git tag v1.6.10-bnb.1
git push origin v1.6.10-bnb.1
```

CircleCI publishes the tagged AMD64 image to the Brand New Box DigitalOcean registry, refreshes the namespace's registry credentials, and deploys the release to the shared cluster with Drydock.

## Rancher sign-in proxy

`rancher-auth/` is a separate service that Executor's Rancher Kubernetes integration signs in through, so connections get long-lived, rolling Rancher API tokens instead of tokens tied to a 16-hour Rancher session. It has its own image and release tags; see [rancher-auth/README.md](rancher-auth/README.md).
