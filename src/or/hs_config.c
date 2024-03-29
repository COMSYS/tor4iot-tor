/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_config.c
 * \brief Implement hidden service configuration subsystem.
 *
 * \details
 *
 * This file has basically one main entry point: hs_config_service_all(). It
 * takes the torrc options and configure hidden service from it. In validate
 * mode, nothing is added to the global service list or keys are not generated
 * nor loaded.
 *
 * A service is configured in two steps. It is first created using the tor
 * options and then put in a staging list. It will stay there until
 * hs_service_load_all_keys() is called. That function is responsible to
 * load/generate the keys for the service in the staging list and if
 * successful, transfert the service to the main global service list where
 * at that point it is ready to be used.
 *
 * Configuration functions are per-version and there is a main generic one for
 * every option that is common to all version (config_generic_service).
 **/

#define HS_CONFIG_PRIVATE

#include "hs_common.h"
#include "hs_config.h"
#include "hs_service.h"
#include "rendservice.h"

/* Using the given list of services, stage them into our global state. Every
 * service version are handled. This function can remove entries in the given
 * service_list.
 *
 * Staging a service means that we take all services in service_list and we
 * put them in the staging list (global) which acts as a temporary list that
 * is used by the service loading key process. In other words, staging a
 * service puts it in a list to be considered when loading the keys and then
 * moved to the main global list. */
static void
stage_services(smartlist_t *service_list)
{
  tor_assert(service_list);

  /* This is v2 specific. Trigger service pruning which will make sure the
   * just configured services end up in the main global list. It should only
   * be done in non validation mode because v2 subsystem handles service
   * object differently. */
  rend_service_prune_list();

  /* Cleanup v2 service from the list, we don't need those object anymore
   * because we validated them all against the others and we want to stage
   * only >= v3 service. And remember, v2 has a different object type which is
   * shadow copied from an hs_service_t type. */
  SMARTLIST_FOREACH_BEGIN(service_list, hs_service_t *, s) {
    if (s->config.version == HS_VERSION_TWO) {
      SMARTLIST_DEL_CURRENT(service_list, s);
      hs_service_free(s);
    }
  } SMARTLIST_FOREACH_END(s);

  /* This is >= v3 specific. Using the newly configured service list, stage
   * them into our global state. Every object ownership is lost after. */
  hs_service_stage_services(service_list);
}

/* Validate the given service against all service in the given list. If the
 * service is ephemeral, this function ignores it. Services with the same
 * directory path aren't allowed and will return an error. If a duplicate is
 * found, 1 is returned else 0 if none found. */
static int
service_is_duplicate_in_list(const smartlist_t *service_list,
                             const hs_service_t *service)
{
  int ret = 0;

  tor_assert(service_list);
  tor_assert(service);

  /* Ephemeral service don't have a directory configured so no need to check
   * for a service in the list having the same path. */
  if (service->config.is_ephemeral) {
    goto end;
  }

  /* XXX: Validate if we have any service that has the given service dir path.
   * This has two problems:
   *
   * a) It's O(n^2), but the same comment from the bottom of
   *    rend_config_services() should apply.
   *
   * b) We only compare directory paths as strings, so we can't
   *    detect two distinct paths that specify the same directory
   *    (which can arise from symlinks, case-insensitivity, bind
   *    mounts, etc.).
   *
   * It also can't detect that two separate Tor instances are trying
   * to use the same HiddenServiceDir; for that, we would need a
   * lock file.  But this is enough to detect a simple mistake that
   * at least one person has actually made. */
  SMARTLIST_FOREACH_BEGIN(service_list, const hs_service_t *, s) {
    if (!strcmp(s->config.directory_path, service->config.directory_path)) {
      log_warn(LD_REND, "Another hidden service is already configured "
                        "for directory %s",
               escaped(service->config.directory_path));
      ret = 1;
      goto end;
    }
  } SMARTLIST_FOREACH_END(s);

 end:
  return ret;
}

/* Helper function: Given an configuration option name, its value, a minimum
 * min and a maxium max, parse the value as a uint64_t. On success, ok is set
 * to 1 and ret is the parsed value. On error, ok is set to 0 and ret must be
 * ignored. This function logs both on error and success. */
static uint64_t
helper_parse_uint64(const char *opt, const char *value, uint64_t min,
                    uint64_t max, int *ok)
{
  uint64_t ret = 0;

  tor_assert(opt);
  tor_assert(value);
  tor_assert(ok);

  *ok = 0;
  ret = tor_parse_uint64(value, 10, min, max, ok, NULL);
  if (!*ok) {
    log_warn(LD_CONFIG, "%s must be between %" PRIu64 " and %"PRIu64
                        ", not %s.",
             opt, min, max, value);
    goto err;
  }
  log_info(LD_CONFIG, "%s was parsed to %" PRIu64, opt, ret);
 err:
  return ret;
}

/* Return true iff the given options starting at line_ for a hidden service
 * contains at least one invalid option. Each hidden service option don't
 * apply to all versions so this function can find out. The line_ MUST start
 * right after the HiddenServiceDir line of this service.
 *
 * This is mainly for usability so we can inform the user of any invalid
 * option for the hidden service version instead of silently ignoring. */
static int
config_has_invalid_options(const config_line_t *line_,
                           const hs_service_t *service)
{
  int ret = 0;
  const char **optlist;
  const config_line_t *line;

  tor_assert(service);
  tor_assert(service->config.version <= HS_VERSION_MAX);

  /* List of options that a v3 service doesn't support thus must exclude from
   * its configuration. */
  const char *opts_exclude_v3[] = {
    "HiddenServiceAuthorizeClient",
    NULL /* End marker. */
  };

  /* Defining the size explicitly allows us to take advantage of the compiler
   * which warns us if we ever bump the max version but forget to grow this
   * array. The plus one is because we have a version 0 :). */
  struct {
    const char **list;
  } exclude_lists[HS_VERSION_MAX + 1] = {
    { NULL }, /* v0. */
    { NULL }, /* v1. */
    { NULL }, /* v2 */
    { opts_exclude_v3 }, /* v3. */
  };

  optlist = exclude_lists[service->config.version].list;
  if (optlist == NULL) {
    /* No exclude options to look at for this version. */
    goto end;
  }
  for (int i = 0; optlist[i]; i++) {
    const char *opt = optlist[i];
    for (line = line_; line; line = line->next) {
      if (!strcasecmp(line->key, "HiddenServiceDir")) {
        /* We just hit the next hidden service, stop right now. */
        goto end;
      }
      if (!strcasecmp(line->key, opt)) {
        log_warn(LD_CONFIG, "Hidden service option %s is incompatible with "
                            "version %" PRIu32 " of service in %s",
                 opt, service->config.version,
                 service->config.directory_path);
        ret = 1;
        /* Continue the loop so we can find all possible options. */
        continue;
      }
    }
  }
 end:
  return ret;
}

/* Validate service configuration. This is used when loading the configuration
 * and once we've setup a service object, it's config object is passed to this
 * function for further validation. This does not validate service key
 * material. Return 0 if valid else -1 if invalid. */
static int
config_validate_service(const hs_service_config_t *config)
{
  tor_assert(config);

  /* Amount of ports validation. */
  if (!config->ports || smartlist_len(config->ports) == 0) {
    log_warn(LD_CONFIG, "Hidden service (%s) with no ports configured.",
             escaped(config->directory_path));
    goto invalid;
  }

  /* Valid. */
  return 0;
 invalid:
  return -1;
}

/* Configuration funcion for a version 3 service. The line_ must be pointing
 * to the directive directly after a HiddenServiceDir. That way, when hitting
 * the next HiddenServiceDir line or reaching the end of the list of lines, we
 * know that we have to stop looking for more options. The given service
 * object must be already allocated and passed through
 * config_generic_service() prior to calling this function.
 *
 * Return 0 on success else a negative value. */
static int
config_service_v3(const config_line_t *line_,
                  hs_service_config_t *config)
{
  int have_num_ip = 0;
  const char *dup_opt_seen = NULL;
  const config_line_t *line;

  tor_assert(config);

  for (line = line_; line; line = line->next) {
    int ok = 0;
    if (!strcasecmp(line->key, "HiddenServiceDir")) {
      /* We just hit the next hidden service, stop right now. */
      break;
    }
    /* Number of introduction points. */
    if (!strcasecmp(line->key, "HiddenServiceNumIntroductionPoints")) {
      config->num_intro_points =
        (unsigned int) helper_parse_uint64(line->key, line->value,
                                           NUM_INTRO_POINTS_DEFAULT,
                                           HS_CONFIG_V3_MAX_INTRO_POINTS,
                                           &ok);
      if (!ok || have_num_ip) {
        if (have_num_ip)
          dup_opt_seen = line->key;
        goto err;
      }
      have_num_ip = 1;
      continue;
    }
  }

  /* We do not load the key material for the service at this stage. This is
   * done later once tor can confirm that it is in a running state. */

  /* We are about to return a fully configured service so do one last pass of
   * validation at it. */
  if (config_validate_service(config) < 0) {
    goto err;
  }

  return 0;
 err:
  if (dup_opt_seen) {
    log_warn(LD_CONFIG, "Duplicate directive %s.", dup_opt_seen);
  }
  return -1;
}

/* Configure a service using the given options in line_ and options. This is
 * called for any service regardless of its version which means that all
 * directives in this function are generic to any service version. This
 * function will also check the validity of the service directory path.
 *
 * The line_ must be pointing to the directive directly after a
 * HiddenServiceDir. That way, when hitting the next HiddenServiceDir line or
 * reaching the end of the list of lines, we know that we have to stop looking
 * for more options.
 *
 * Return 0 on success else -1. */
static int
config_generic_service(const config_line_t *line_,
                       const or_options_t *options,
                       hs_service_t *service)
{
  int dir_seen = 0;
  const config_line_t *line;
  hs_service_config_t *config;
  /* If this is set, we've seen a duplicate of this option. Keep the string
   * so we can log the directive. */
  const char *dup_opt_seen = NULL;
  /* These variables will tell us if we ever have duplicate. */
  int have_version = 0, have_allow_unknown_ports = 0;
  int have_dir_group_read = 0, have_max_streams = 0;
  int have_max_streams_close = 0;
  int have_delegation = 0;

  tor_assert(line_);
  tor_assert(options);
  tor_assert(service);

  /* Makes thing easier. */
  config = &service->config;

  /* The first line starts with HiddenServiceDir so we consider what's next is
   * the configuration of the service. */
  for (line = line_; line ; line = line->next) {
    int ok = 0;

    /* This indicate that we have a new service to configure. */
    if (!strcasecmp(line->key, "HiddenServiceDir")) {
      /* This function only configures one service at a time so if we've
       * already seen one, stop right now. */
      if (dir_seen) {
        break;
      }
      /* Ok, we've seen one and we are about to configure it. */
      dir_seen = 1;
      config->directory_path = tor_strdup(line->value);
      log_info(LD_CONFIG, "HiddenServiceDir=%s. Configuring...",
               escaped(config->directory_path));
      continue;
    }
    if (BUG(!dir_seen)) {
      goto err;
    }
    /* Version of the service. */
    if (!strcasecmp(line->key, "HiddenServiceVersion")) {
      service->config.version =
        (uint32_t) helper_parse_uint64(line->key, line->value, HS_VERSION_MIN,
                                       HS_VERSION_MAX, &ok);
      if (!ok || have_version) {
        if (have_version)
          dup_opt_seen = line->key;
        goto err;
      }
      have_version = 1;
      continue;
    }
    /* Virtual port. */
    if (!strcasecmp(line->key, "HiddenServicePort")) {
      char *err_msg = NULL;
      /* XXX: Can we rename this? */
      rend_service_port_config_t *portcfg =
        rend_service_parse_port_config(line->value, " ", &err_msg);
      if (!portcfg) {
        if (err_msg) {
          log_warn(LD_CONFIG, "%s", err_msg);
        }
        tor_free(err_msg);
        goto err;
      }
      tor_assert(!err_msg);
      smartlist_add(config->ports, portcfg);
      log_info(LD_CONFIG, "HiddenServicePort=%s for %s",
               line->value, escaped(config->directory_path));
      continue;
    }
    /* Do we allow unknown ports. */
    if (!strcasecmp(line->key, "HiddenServiceAllowUnknownPorts")) {
      config->allow_unknown_ports =
        (unsigned int) helper_parse_uint64(line->key, line->value, 0, 1, &ok);
      if (!ok || have_allow_unknown_ports) {
        if (have_allow_unknown_ports)
          dup_opt_seen = line->key;
        goto err;
      }
      have_allow_unknown_ports = 1;
      continue;
    }
    /* Directory group readable. */
    if (!strcasecmp(line->key, "HiddenServiceDirGroupReadable")) {
      config->dir_group_readable =
        (unsigned int) helper_parse_uint64(line->key, line->value, 0, 1, &ok);
      if (!ok || have_dir_group_read) {
        if (have_dir_group_read)
          dup_opt_seen = line->key;
        goto err;
      }
      have_dir_group_read = 1;
      continue;
    }
    /* Maximum streams per circuit. */
    if (!strcasecmp(line->key, "HiddenServiceMaxStreams")) {
      config->max_streams_per_rdv_circuit =
        helper_parse_uint64(line->key, line->value, 0,
                            HS_CONFIG_MAX_STREAMS_PER_RDV_CIRCUIT, &ok);
      if (!ok || have_max_streams) {
        if (have_max_streams)
          dup_opt_seen = line->key;
        goto err;
      }
      have_max_streams = 1;
      continue;
    }
    /* Maximum amount of streams before we close the circuit. */
    if (!strcasecmp(line->key, "HiddenServiceMaxStreamsCloseCircuit")) {
      config->max_streams_close_circuit =
        (unsigned int) helper_parse_uint64(line->key, line->value, 0, 1, &ok);
      if (!ok || have_max_streams_close) {
        if (have_max_streams_close)
          dup_opt_seen = line->key;
        goto err;
      }
      have_max_streams_close = 1;
      continue;
    }
    /* Maximum amount of streams before we close the circuit. */
    if (!strcasecmp(line->key, "HiddenServiceDelegation")) {
    	config->is_delegation =
    			(unsigned int) helper_parse_uint64(line->key, line->value, 0, 1, &ok);
    	if (!ok || have_delegation) {
    		if (have_delegation)
    			dup_opt_seen = line->key;
    		goto err;
    	}
    	have_delegation = 1;
    	continue;
    }
  }

  /* Check if we are configured in non anonymous mode meaning every service
   * becomes a single onion service. */
  if (rend_service_non_anonymous_mode_enabled(options)) {
    config->is_single_onion = 1;
    /* We will add support for IPv6-only v3 single onion services in a future
     * Tor version. This won't catch "ReachableAddresses reject *4", but that
     * option doesn't work anyway. */
    if (options->ClientUseIPv4 == 0 && config->version == HS_VERSION_THREE) {
      log_warn(LD_CONFIG, "IPv6-only v3 single onion services are not "
               "supported. Set HiddenServiceSingleHopMode 0 and "
               "HiddenServiceNonAnonymousMode 0, or set ClientUseIPv4 1.");
      goto err;
    }
  }

  /* Success */
  return 0;
 err:
  if (dup_opt_seen) {
    log_warn(LD_CONFIG, "Duplicate directive %s.", dup_opt_seen);
  }
  return -1;
}

/* Configure a service using the given line and options. This function will
 * call the corresponding configuration function for a specific service
 * version and validate the service against the other ones. On success, add
 * the service to the given list and return 0. On error, nothing is added to
 * the list and a negative value is returned. */
static int
config_service(const config_line_t *line, const or_options_t *options,
               smartlist_t *service_list)
{
  int ret;
  hs_service_t *service = NULL;

  tor_assert(line);
  tor_assert(options);
  tor_assert(service_list);

  /* We have a new hidden service. */
  service = hs_service_new(options);
  /* We'll configure that service as a generic one and then pass it to a
   * specific function according to the configured version number. */
  if (config_generic_service(line, options, service) < 0) {
    goto err;
  }
  tor_assert(service->config.version <= HS_VERSION_MAX);
  /* Before we configure the service on a per-version basis, we'll make
   * sure that this set of options for a service are valid that is for
   * instance an option only for v2 is not used for v3. */
  if (config_has_invalid_options(line->next, service)) {
    goto err;
  }
  /* Check permission on service directory that was just parsed. And this must
   * be done regardless of the service version. Do not ask for the directory
   * to be created, this is done when the keys are loaded because we could be
   * in validation mode right now. */
  if (hs_check_service_private_dir(options->User,
                                   service->config.directory_path,
                                   service->config.dir_group_readable,
                                   0) < 0) {
    goto err;
  }
  /* Different functions are in charge of specific options for a version. We
   * start just after the service directory line so once we hit another
   * directory line, the function knows that it has to stop parsing. */
  switch (service->config.version) {
  case HS_VERSION_TWO:
    ret = rend_config_service(line->next, options, &service->config);
    break;
  case HS_VERSION_THREE:
    ret = config_service_v3(line->next, &service->config);
    break;
  default:
    /* We do validate before if we support the parsed version. */
    tor_assert_nonfatal_unreached();
    goto err;
  }
  if (ret < 0) {
    goto err;
  }
  /* We'll check if this service can be kept depending on the others
   * configured previously. */
  if (service_is_duplicate_in_list(service_list, service)) {
    goto err;
  }
  /* Passes, add it to the given list. */
  smartlist_add(service_list, service);
  return 0;

 err:
  hs_service_free(service);
  return -1;
}

/* From a set of <b>options</b>, setup every hidden service found. Return 0 on
 * success or -1 on failure. If <b>validate_only</b> is set, parse, warn and
 * return as normal, but don't actually change the configured services. */
int
hs_config_service_all(const or_options_t *options, int validate_only)
{
  int dir_option_seen = 0, ret = -1;
  const config_line_t *line;
  smartlist_t *new_service_list = NULL;

  tor_assert(options);

  /* Newly configured service are put in that list which is then used for
   * validation and staging for >= v3. */
  new_service_list = smartlist_new();

  for (line = options->RendConfigLines; line; line = line->next) {
    /* Ignore all directives that aren't the start of a service. */
    if (strcasecmp(line->key, "HiddenServiceDir")) {
      if (!dir_option_seen) {
        log_warn(LD_CONFIG, "%s with no preceding HiddenServiceDir directive",
                 line->key);
        goto err;
      }
      continue;
    }
    /* Flag that we've seen a directory directive and we'll use it to make
     * sure that the torrc options ordering is actually valid. */
    dir_option_seen = 1;

    /* Try to configure this service now. On success, it will be added to the
     * list and validated against the service in that same list. */
    if (config_service(line, options, new_service_list) < 0) {
      goto err;
    }
  }

  /* In non validation mode, we'll stage those services we just successfully
   * configured. Service ownership is transfered from the list to the global
   * state. If any service is invalid, it will be removed from the list and
   * freed. All versions are handled in that function. */
  if (!validate_only) {
    stage_services(new_service_list);
  } else {
    /* We've just validated that we were able to build a clean working list of
     * services. We don't need those objects anymore. */
    SMARTLIST_FOREACH(new_service_list, hs_service_t *, s,
                      hs_service_free(s));
    /* For the v2 subsystem, the configuration function adds the service
     * object to the staging list and it is transferred in the main list
     * through the prunning process. In validation mode, we thus have to purge
     * the staging list so it's not kept in memory as valid service. */
    rend_service_free_staging_list();
  }

  /* Success. Note that the service list has no ownership of its content. */
  ret = 0;
  goto end;

 err:
  SMARTLIST_FOREACH(new_service_list, hs_service_t *, s, hs_service_free(s));

 end:
  smartlist_free(new_service_list);
  /* Tor main should call the free all function on error. */
  return ret;
}

