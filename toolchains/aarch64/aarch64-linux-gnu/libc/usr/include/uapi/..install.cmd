cmd_/home/tcwg-buildslave/workspace/tcwg-make-release/label/docker-trusty-amd64-tcwg-build/target/aarch64-linux-gnu/_build/sysroots/aarch64-linux-gnu/usr/include/uapi/.install := /bin/bash scripts/headers_install.sh /home/tcwg-buildslave/workspace/tcwg-make-release/label/docker-trusty-amd64-tcwg-build/target/aarch64-linux-gnu/_build/sysroots/aarch64-linux-gnu/usr/include/uapi ./include/uapi ; /bin/bash scripts/headers_install.sh /home/tcwg-buildslave/workspace/tcwg-make-release/label/docker-trusty-amd64-tcwg-build/target/aarch64-linux-gnu/_build/sysroots/aarch64-linux-gnu/usr/include/uapi ./include ; /bin/bash scripts/headers_install.sh /home/tcwg-buildslave/workspace/tcwg-make-release/label/docker-trusty-amd64-tcwg-build/target/aarch64-linux-gnu/_build/sysroots/aarch64-linux-gnu/usr/include/uapi ./include/generated/uapi ; for F in ; do echo "\#include <asm-generic/$$F>" > /home/tcwg-buildslave/workspace/tcwg-make-release/label/docker-trusty-amd64-tcwg-build/target/aarch64-linux-gnu/_build/sysroots/aarch64-linux-gnu/usr/include/uapi/$$F; done; touch /home/tcwg-buildslave/workspace/tcwg-make-release/label/docker-trusty-amd64-tcwg-build/target/aarch64-linux-gnu/_build/sysroots/aarch64-linux-gnu/usr/include/uapi/.install
