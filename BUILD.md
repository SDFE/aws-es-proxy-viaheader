# Build

***Note**: versioned dependencies has been removed for simplicity, once we have some experience with vgo & co. we will be adding versioned dependencies back in, however, for now this is sufficient and as of 30/8/2018 the build works*

### requirements
- go 1.20

### build it

create d docker image to run the build for you, this way you're not required to potentially pollute your environment with depdendencies you don't usually need

```
docker build -f Dockerfile.BUILD -t local/aws-es-proxy-build:latest .
```

then build the binary (linux only)

```
rm -rf dist/
docker run --rm -v $(pwd)/dist:/dist local/aws-es-proxy-build:latest
```

# Docker

use the default Dockerfile to build a container that runs `aws-es-proxy` _"anywhere"_

```
docker build -t local/aws-es-proxy:latest .
```

# Cleanup

i'd suggest to remove the local image after the build is complete

```
docker rmi local/aws-es-proxy-build:latest
```
