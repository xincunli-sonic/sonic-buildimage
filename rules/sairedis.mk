# sairedis package

LIBSAIREDIS = libsairedis_1.0.0_$(CONFIGURED_ARCH).deb
$(LIBSAIREDIS)_DPKG_TARGET = binary-sairedis
$(LIBSAIREDIS)_SRC_PATH = $(SRC_PATH)/sonic-sairedis
$(LIBSAIREDIS)_DEPENDS += $(LIBSWSSCOMMON_DEV)
$(LIBSAIREDIS)_RDEPENDS += $(LIBSWSSCOMMON)
$(LIBSAIREDIS)_DEB_BUILD_OPTIONS = nocheck
SONIC_DPKG_DEBS += $(LIBSAIREDIS)

LIBSAIREDIS_DEV = libsairedis-dev_1.0.0_$(CONFIGURED_ARCH).deb
$(eval $(call add_derived_package,$(LIBSAIREDIS),$(LIBSAIREDIS_DEV)))

LIBSAIVS = libsaivs_1.0.0_$(CONFIGURED_ARCH).deb
$(eval $(call add_derived_package,$(LIBSAIREDIS),$(LIBSAIVS)))

LIBSAIVS_DEV = libsaivs-dev_1.0.0_$(CONFIGURED_ARCH).deb
$(eval $(call add_derived_package,$(LIBSAIREDIS),$(LIBSAIVS_DEV)))
$(LIBSAIVS_DEV)_DEPENDS += $(LIBSAIVS)


LIBSAIMETADATA = libsaimetadata_1.0.0_$(CONFIGURED_ARCH).deb
$(eval $(call add_derived_package,$(LIBSAIREDIS),$(LIBSAIMETADATA)))

LIBSAIMETADATA_DEV = libsaimetadata-dev_1.0.0_$(CONFIGURED_ARCH).deb
$(LIBSAIMETADATA_DEV)_DEPENDS += $(LIBSAIMETADATA)
$(eval $(call add_derived_package,$(LIBSAIREDIS),$(LIBSAIMETADATA_DEV)))

LIBSAIREDIS_DBG = libsairedis-dbg_1.0.0_$(CONFIGURED_ARCH).deb
$(LIBSAIREDIS_DBG)_DEPENDS += $(LIBSAIREDIS)
$(LIBSAIREDIS_DBG)_RDEPENDS += $(LIBSAIREDIS)
$(eval $(call add_derived_package,$(LIBSAIREDIS),$(LIBSAIREDIS_DBG)))

LIBSAIVS_DBG = libsaivs-dbg_1.0.0_$(CONFIGURED_ARCH).deb
$(LIBSAIVS_DBG)_DEPENDS += $(LIBSAIVS)
$(LIBSAIVS_DBG)_RDEPENDS += $(LIBSAIVS)
$(eval $(call add_derived_package,$(LIBSAIREDIS),$(LIBSAIVS_DBG)))


LIBSAIMETADATA_DBG = libsaimetadata-dbg_1.0.0_$(CONFIGURED_ARCH).deb
$(LIBSAIMETADATA_DBG)_DEPENDS += $(LIBSAIMETADATA)
$(LIBSAIMETADATA_DBG)_RDEPENDS += $(LIBSAIMETADATA)
$(eval $(call add_derived_package,$(LIBSAIREDIS),$(LIBSAIMETADATA_DBG)))

# The .c, .cpp, .h & .hpp files under src/{$DBG_SRC_ARCHIVE list}
# are archived into debug one image to facilitate debugging.
#
DBG_SRC_ARCHIVE += sonic-sairedis
