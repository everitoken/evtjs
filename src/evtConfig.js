/**
 * EVTJS: JavaScript API Binding for everiToken blockchain
 *
 * Copyright(C) everiToken core team
 * Under MIT license
 *
 * This project is based on some projects under MIT license
 * For detail, please visit our github or read README.md for
 * more informatino.
 */

/**
 * represents EvtConfig
 */
class EvtConfig {
  constructor(config = null) {
    // set default endpoint
    /**
     * @member {Object} endpoint
     */
    this.endpoint = EvtConfig.getTestNetEndpoint();
    // copy user's config
    if (config) {
      Object.assign(this, config);
    }
    // fill default endpoint settings
    if (!this.endpoint) this.endpoint = {};
    if (!this.endpoint.port) this.endpoint.port = 8888;
    if (!this.endpoint.protocol) this.endpoint.protocol = "https";
    if (!this.networkTimeout) this.networkTimeout = 15000;
    if (this.syncNodeTime === undefined) this.syncNodeTime = true;
  }
}

/**
 * Get TestNet endpoint for everiToken
 */
EvtConfig.getTestNetEndpoint = function() {
  return Object.assign(
    {},
    {
      host: "testnet1.everitoken.io",
      port: 443,
      protocol: "https"
    }
  );
};

/**
 * Get LocalNet EndPoint for everiToken
 */
EvtConfig.getLocalNetEndpoint = function(host = "127.0.0.1", port = 8888) {
  return Object.assign(
    {},
    {
      host: host,
      port: port,
      protocol: "http"
    }
  );
};

module.exports = EvtConfig;
