# seccomp_fake_xattr

Emulate extended attribute ([xattr](https://man7.org/linux/man-pages/man7/xattr.7.html)) operations in user space.

All xattr related syscalls are intercepted using the seccomp user-space notification mechanism ([seccomp_unotify](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)) and their results emulated by a user-space handler.
The handler stores its own xattr database in memory, without ever accessing extended attributes on the underlying file system.

The main use of this is for system / distribution image builds.
It allows the build to set extended attributes that it would normally not have access to (i.e. if the build is running inside an unprivileged container or on a host with security modules loaded) in such a way that later tar archive / disk image / etc creation steps see and includes these attributes correctly.


## Usage

```
./fake_xattr [command] [args...]
```

`[command]` and all of its child processes will then run with their xattr syscalls intercepted and emulated.

> [!IMPORTANT]
> In order to install seccomp filters for its child processes, `fake_xattr` needs the `CAP_SYS_ADMIN` capability in its user namspace.
> Therefore, as an unprivileged user, it is necessary to run it with `unshare --map-root-user --map-auto ./fake_xattr` or similar means.


## Build

To build the main tool run

```
make fake_xattr
```

This requires a standard linux build environment to be present. See [Dev Container](#dev-container) for the recommended way of setting this up.

### Test

To build and run the unit and integration tests run

```
make test
```

## Dev Container

To simplify the build process this project includes a dev container. This can either be used directly by [VS Code](https://code.visualstudio.com/docs/devcontainers/containers) and [GitHub Codespaces](https://docs.github.com/en/codespaces) or as a regular container.

To use it as a regular container run

```
podman build -t dev .devcontainer
podman run --rm \
	--security-opt seccomp=unconfined \
	--security-opt label=disable \
	--security-opt apparmor=unconfined \
	--userns keep-id:uid=1000,gid=1000 \
	-v "$PWD:/home/dev/workdir" \
	-w /home/dev/workdir \
	-it dev
```

> [!NOTE]
> The `--userns keep-id:uid=1000,gid=1000` is needed because the dev container is configured to drop privileges to a dev user (`uid=1000 gid=1000`), while podman by default will map your host system user to `uid=0 gid=0`.
> Thus the work directory would not otherwise be writable by the dev user.

> [!TIP]
> Older versions of podman do not support the `--userns keep-id:uid=1000,gid=1000` parameter.
> For these versions you will need to use the long form:
> `--uidmap 0:1:1000 --uidmap 1000:0:1 --uidmap 1001:1001:64536 --gidmap 0:1:1000 --gidmap 1000:0:1 --gidmap 1001:1001:64536`
> This does exactly the same, just in a more verbose format.

> [!TIP]
> Running the dev container with docker instead of podman may work, but is not supported and you will need to setup a uid_map from your host user to the dev user inside the container.
