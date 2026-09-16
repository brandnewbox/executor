# Executor

Brand New Box build of [Executor](https://executor.sh) with the [1Password plugin](https://github.com/UsefulSoftwareCo/executor/tree/main/packages/plugins/onepassword) enabled.

```text
registry.digitalocean.com/brandnewbox/executor
```

The image otherwise follows Executor's upstream self-hosted build. Upstream source is pinned by `EXECUTOR_VERSION` in the `Dockerfile`.

## Release

Create a tag using the upstream version plus a BNB build number:

```sh
git tag v1.6.8-bnb.1
git push origin v1.6.8-bnb.1
```

CircleCI publishes the tagged AMD64 image to the Brand New Box DigitalOcean registry.
