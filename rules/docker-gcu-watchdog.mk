# docker image for GCU watchdog (Rust, gRPC)
#
# The watchdog monitors the integrity of the GCU Python venv at
# /opt/gcu-venv/lib/python*/site-packages/generic_config_updater/.
#
# The Rust binary is built inside a multi-stage Dockerfile (builder stage uses
# rustup to install Rust toolchain and runs 'cargo build --release').
# The resulting binary is copied into the minimal final runtime stage.
#
# The Rust source lives in src/gcu-watchdog/ and is copied into the Docker
# build context under the 'watchdog/' subdirectory by the build system.

DOCKER_GCU_WATCHDOG_STEM = docker-gcu-watchdog
DOCKER_GCU_WATCHDOG = $(DOCKER_GCU_WATCHDOG_STEM).gz
DOCKER_GCU_WATCHDOG_DBG = $(DOCKER_GCU_WATCHDOG_STEM)-$(DBG_IMAGE_MARK).gz

$(DOCKER_GCU_WATCHDOG)_LOAD_DOCKERS = $(DOCKER_CONFIG_ENGINE_BOOKWORM)
$(DOCKER_GCU_WATCHDOG)_PATH = $(DOCKERS_PATH)/$(DOCKER_GCU_WATCHDOG_STEM)

$(DOCKER_GCU_WATCHDOG)_VERSION = 1.0.0
$(DOCKER_GCU_WATCHDOG)_PACKAGE_NAME = gcu_watchdog

SONIC_DOCKER_IMAGES += $(DOCKER_GCU_WATCHDOG)
SONIC_BOOKWORM_DOCKERS += $(DOCKER_GCU_WATCHDOG)
ifeq ($(INCLUDE_GCU_WATCHDOG), y)
SONIC_INSTALL_DOCKER_IMAGES += $(DOCKER_GCU_WATCHDOG)
endif

SONIC_DOCKER_DBG_IMAGES += $(DOCKER_GCU_WATCHDOG_DBG)
SONIC_BOOKWORM_DBG_DOCKERS += $(DOCKER_GCU_WATCHDOG_DBG)
ifeq ($(INCLUDE_GCU_WATCHDOG), y)
SONIC_INSTALL_DOCKER_DBG_IMAGES += $(DOCKER_GCU_WATCHDOG_DBG)
endif

# Container name uses hyphen (kebab-case) to match SONiC naming convention;
# the Rust binary uses underscore (snake_case) internally.
$(DOCKER_GCU_WATCHDOG)_CONTAINER_NAME = gcu-watchdog
$(DOCKER_GCU_WATCHDOG)_PACKAGE_NAME   = gcu-watchdog
$(DOCKER_GCU_WATCHDOG)_RUN_OPT += -t --pid=host
$(DOCKER_GCU_WATCHDOG)_RUN_OPT += -v /etc/localtime:/etc/localtime:ro
# Mount the GCU named volume read-only — must match the volume name used by
# docker-gcu so both containers see the same venv filesystem.
$(DOCKER_GCU_WATCHDOG)_RUN_OPT += -v gcu-venv:/opt/gcu-venv:ro

# ---------------------------------------------------------------------------
# Pre-build: make the Rust source available inside the Docker build context.
#
# The Rust source lives in src/gcu-watchdog/ (outside the docker dir).
# The Dockerfile does 'COPY watchdog/ ./' which expects 'watchdog/' to exist
# under $(DOCKER_GCU_WATCHDOG)_PATH = dockers/docker-gcu-watchdog/.
# We create a relative symlink so docker build can reach the source without
# duplicating files.  The symlink is .gitignored (see .gitignore).
# ---------------------------------------------------------------------------
GCU_WATCHDOG_DOCKER_DIR = $(DOCKERS_PATH)/$(DOCKER_GCU_WATCHDOG_STEM)
GCU_WATCHDOG_SRC_DIR    = $(abspath src/gcu-watchdog)

$(DOCKER_GCU_WATCHDOG): $(GCU_WATCHDOG_DOCKER_DIR)/watchdog

$(GCU_WATCHDOG_DOCKER_DIR)/watchdog:
	@ln -sfn $(GCU_WATCHDOG_SRC_DIR) $@
	@echo "Linked $(GCU_WATCHDOG_SRC_DIR) -> $@"
