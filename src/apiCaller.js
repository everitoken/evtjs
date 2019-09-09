const ecc = require("./ecc/index");
const { signHash } = ecc;
const EvtConfig = require("./evtConfig");
const { fetch } = require("./fetch");
const ByteBuffer = require("bytebuffer");
const { EvtAction } = require("./action");
const Logger = require("./logger");
const EvtKey = require("./key");
const EvtLink = require("./evtLink");
const Structs = require("./structs");
const Fcbuffer = require("evt-fcbuffer");

let structs = Structs({ });

/**
 * APICaller for everiToken
*/
class APICaller {
    /**
     * Creates a new APICaller.
     * @param {EvtConfig} config 
     */
    constructor(config) {
        config = config || new EvtConfig();
        if (typeof config == "object" && config != null && !(config instanceof EvtConfig)) {
            config = new EvtConfig(config);
        }

        /** @member {EvtConfig} evtConfig */
        this.config = config || new EvtConfig();

        if (!this.config.signProvider) {
            this.config.signProvider = defaultSignProvider(this, this.config);
        }

        this.getNodeTimestamp();
        // try to get info to get the diff from local time to server time. It is useful to improve the rate of success in everiPay / everiPass
        /*this.timeDiff = null;
        this.getNodeTimestamp().then(() => {
            this.timeDiff = null;
        }).catch(() => { });*/
    }

    /**
     * Get the time of the server.
     */
    async getNodeTimestamp() {
        if (this.timeDiff == null) {
            try {
                await this.getInfo({ timeout: 2000 });
            }
            catch (e) {
                console.log(e);
            }
        }

        if (this.timeDiff == null) {
            return new Date().getTime();
        }

        return new Date().getTime() + this.timeDiff;
    }

    /**
     * Call everiToken APIs directly, not suggested to use by user
     * @param {*} request 
     */
    async __callAPI(request) {
        var url = this.config.endpoint.protocol + "://" + this.config.endpoint.host + ":" + this.config.endpoint.port + request.url;

        Logger.verbose("[fetch] begin sending request: " + url + ": " + JSON.stringify(request, null, 4));

        let requestOptions = {
            method: request.method,
            body: request.body ? JSON.stringify(request.body) : undefined,
            headers: {
                "Content-Type": "application/json"
            },
            networkTimeout: request.networkTimeout || this.config.networkTimeout
        };

        let res, ret;
        if (this.config.httpRequestHook) {
            res = await this.config.httpRequestHook(url, requestOptions);

            if (typeof res == "string") {
                ret = JSON.parse(res);
            }
            else {
                ret = res;
            }
        }
        else {
            res = await fetch(url, requestOptions);
            ret = await res.json();
        }

        if (ret && ret.code && ret.message && ret.error) {
            this.__throwServerResponseError(ret);
        }
        if (!ret) {
            throw new Error("No response or not a valid json from http server");
        }

        return ret;
    }

    /**
     * get information from everiToken chain node
     */
    async getInfo(options) {
        if (this.__lastTimeGetInfo && this.__cachedInfo) {
            if (new Date().valueOf() - this.__lastTimeGetInfo < 5000) {
                return this.__cachedInfo;
            }
        }

        this.__lastTimeGetInfo = new Date().valueOf();

        options = options || { };
        var info = await this.__callAPI({
            url: "/v1/chain/get_info",
            method: "GET",
            networkTimeout: options.timeout || this.config.networkTimeout
        });

        // do not cache the result because it may expire at any time
        this.__cachedInfo = info;

        // check version of remote net
        if (!info.evt_api_version.startsWith("2.") && !info.evt_api_version.startsWith("3.") && !info.evt_api_version.startsWith("4.")) {
            throw new Error(`[Fatal] The API version of remote net (${info.evt_api_version}) is not compatible with current evtjs's version. Please upgrade your evtjs's version.`);
        }

        this.__node_evt_api_version = info.evt_api_version;

        if (info.enabled_plugins && !info.enabled_plugins.includes("evt::history_plugin")) {
            this.__node_history_plugin_enabled = false;
        }
        else {
            this.__node_history_plugin_enabled = true;
        }

        if (info.head_block_time.length == 19) {
            info.head_block_time += "Z";
        }

        this.timeDiff = new Date(info.head_block_time).getTime() + 70 - new Date().getTime();

        // sync time to global
        if (global || window) {
            (global || window).__evtjs_timeDiff = this.timeDiff;
        }

        return info;
    }

    /**
     * get domain list a user created, make sure you have history_plugin enabled on the chain node
     * @param {*} publicKeys a array or a single value which represents public keys you want to query
     */
    async getCreatedDomains(publicKeys) {
        let res = await this.__callAPI({
            url: "/v1/history/get_domains",
            method: "POST",
            body: {
                keys: Array.isArray(publicKeys) ? publicKeys : [ publicKeys ]
            },
            sign: false // no need to sign
        });

        if (Array.isArray(res)) {
            return res.map(x => { return { name: x }; });
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * Provide all the public keys its has and this API will response with all the symbol ids of the fungibles that account create.
     * @param {*} publicKeys a array or a single value which represents public keys you want to query
     */
    async getCreatedFungibles(publicKeys) {
        let res = await this.__callAPI({
            url: "/v1/history/get_fungibles",
            method: "POST",
            body: {
                keys: Array.isArray(publicKeys) ? publicKeys : [ publicKeys ]
            },
            sign: false // no need to sign
        });

        if (Array.isArray(res)) {
            return { ids: res };
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * Get required keys for suspended transactions
     * @param {string} proposalName The proposal name you want to sign
     * @param {string[]} availableKeys array of public keys you own
     */
    async getRequiredKeysForSuspendedTransaction(proposalName, availableKeys) {
        // check parameters
        if (!proposalName || (typeof proposalName !== "string")) throw new Error("invalid proposalName");
        if (!availableKeys || (!Array.isArray(availableKeys))) throw new Error("invalid availableKeys");

        // call APIs
        let res = await this.__callAPI({
            url: "/v1/chain/get_suspend_required_keys",
            method: "POST",
            body: {
                name: proposalName,
                available_keys: availableKeys
            },
            sign: false // no need to sign
        });

        if (res && res.required_keys && Array.isArray(res.required_keys)) {
            return res.required_keys;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * Get detail information of a suspended transaction
     * @param {string} proposalName The proposal name you want to query
     */
    async getSuspendedTransactionDetail(proposalName) {
        // check parameters
        if (!proposalName || (typeof proposalName !== "string")) throw new Error("invalid proposalName");

        // call APIs
        let res = await this.__callAPI({
            url: "/v1/evt/get_suspend",
            method: "POST",
            body: {
                name: proposalName
            },
            sign: false // no need to sign
        });

        if (res && res.name && res.proposer) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * get a list of groups, each group in it must has a group key which is contained by provided public keys. Make sure you have history_plugin enabled on the chain node
     * @param {*} publicKeys a array or a single value which represents public keys you want to query
     */
    async getManagedGroups(publicKeys) {
        let res = await this.__callAPI({
            url: "/v1/history/get_groups",
            method: "POST",
            body: {
                keys: Array.isArray(publicKeys) ? publicKeys : [ publicKeys ]
            },
            sign: false // no need to sign
        });

        if (Array.isArray(res)) {
            return res.map(x => { return { name: x }; });
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * get owned token list for accounts. Make sure you have history_plugin enabled on the chain node
     * @param {*} publicKeys a array or a single value which represents public keys you want to query
     * @param {boolean} groupByDomain whether group the returned values by domain, only avaiable for chain version >= 3
     */
    async getOwnedTokens(publicKeys, groupByDomain = false) {
        let res = await this.__callAPI({
            url: "/v1/history/get_tokens",
            method: "POST",
            body: {
                keys: Array.isArray(publicKeys) ? publicKeys : [ publicKeys ]
            },
            sign: false // no need to sign
        });

        if (Array.isArray(res)) {
            if (groupByDomain) throw new Error("chain version < 3 not support group by domain");
            
            // chain version < 3
            return res.map(x => { return { name: x.substr(x.lastIndexOf("-") + 1), domain: x.substr(0, x.lastIndexOf("-")) }; });
        }
        else if (res.error) {
            this.__throwServerResponseError(res);
        }
        else {
            if (groupByDomain) {
                return res;
            }
            // chain version >= 3
            let ret = [ ];

            for (let key in res) {
                for (let value of res[key]) {
                    ret.push({ name: value, domain: key });
                }
            }

            return ret;
        }
    }

    /**
     * get specific token's detail information.
     * @param {string} domain the domain to query
     * @param {string} name the name to query
     */
    async getToken(domain, name) {
        let res = await this.__callAPI({
            url: "/v1/evt/get_token",
            method: "POST",
            body: {
                domain, name
            },
            sign: false // no need to sign
        });

        if (!res.code || !res.error) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * batch get tokens from one domain, the max allowed to get in one request to get is 100.
     * @param {string} domain the domain to query
     * @param {number} skip the offset of request data
     * @param {number} take the amount of data to get
     */
    async getTokens(domain, skip, take) {

        if (typeof domain !== "string" || !Number.isInteger(skip) || !Number.isInteger(take)) throw new Error('please check your datatype of params');

        let res = await this.__callAPI({
            url: "/v1/evt/get_tokens",
            method: "POST",
            body: {
                domain, skip, take
            },
            sign: false // no need to sign
        });

        if (!res.code || !res.error) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * Query actions by domain, key and action names. Make sure you have history_plugin enabled on the chain node
     * @param {*} params
     */
    async getActions(params) {
        if (typeof params !== "object") throw new Error("invalid params");
        if (!params || !params.domain) throw new Error("invalid params: domain is required");

        let res = await this.__callAPI({
            url: "/v1/history/get_actions",
            method: "POST",
            body: params,
            sign: false // no need to sign
        });

        if (Array.isArray(res)) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * get detail information about a transaction by its id.
     * @param {string} id the id of the transaction.
     * @param {string} blockNum (optional) the block num of the transaction. If not provided, the system will find it for you.
     * @param {object} options (optional) addtional options. available field: usingHistoryPlugin - (default true) whether to use history plugin. If you want to query transactions on a node that doesn't have history plugin, please set it to false. But in this case you can't query old transactions.
     */
    async getTransactionDetailById(id, blockNum = undefined, options = undefined) {
        if (typeof id !== "string" || !id) throw new Error("invalid transaction id");
        let _options = {
            usingHistoryPlugin: true
        };

        if (options) {
            Object.assign(_options, options);
        }

        let res = await this.__callAPI({
            url: _options.usingHistoryPlugin == false ? "/v1/chain/get_transaction" : "/v1/history/get_transaction",
            method: "POST",
            body: { id, block_num: blockNum },
            sign: false // no need to sign
        });

        if (res && res.id && res.transaction) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * query all the actions of one transaction by its id. Different from `getTransactionDetailById`, this function will return all the actions including actions generated by the chain.
     * @param {string} id the id of the transaction.
     */
    async getTransactionActions(id) {
        if (typeof id !== "string" || !id) throw new Error("invalid transaction id");

        let res = await this.__callAPI({
            url: "/v1/history/get_transaction_actions",
            method: "POST",
            body: { id },
            sign: false // no need to sign
        });

        if (!res) return [ ];
        return res;
    }

    /**
     * query block information by num or id
     * @param {string} blockNumOrId id or num of the block
     * @returns {object} information
     */
    async getBlockDetail(blockNumOrId) {
        if (typeof blockNumOrId !== "string" || !blockNumOrId) throw new Error("invalid query key, it can be either block_num or block_id");

        let res = await this.__callAPI({
            url: "/v1/chain/get_block",
            method: "POST",
            body: { block_num_or_id: blockNumOrId },
            sign: false // no need to sign
        });

        if (res && res.id && res.block_num) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * query block header information by num or id
     * @param {string} key id or num of the block
     * @returns {object} header state
     */
    /*async getBlockHeaderState(key) {
        if (typeof key !== "string" || !key) throw new Error("invalid query key, it can be either block_num or block_id");

        let res = await this.__callAPI({
            url: "/v1/chain/get_block_header_state",
            method: "POST",
            body: { block_num_or_id: key },
            sign: false // no need to sign
        });

        if (!res.error) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }*/

    /**
     * (deprecated) get transaction id for a linkId
     * @param {string} id the linkId
     * @deprecated
     */
    async getTransactionIdForLinkId(id) {
        console.warn("[warn] getTransactionIdForLinkId is deprecated, please use getStatusForLinkId instead.");

        if (typeof id !== "string" || !id) throw new Error("invalid link id");

        let res = await this.__callAPI({
            url: "/v1/chain/get_trx_id_for_link_id",
            method: "POST",
            body: { link_id: id },
            sign: false // no need to sign
        });

        if (res && res.trx_id) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * get transaction status of an evtLink.
     * Note: please check the `linkId` property of the return value. If it is not the same one as your expectation, just drop it. It is possible if you use a same callback for two calls.
     * @param {string} linkId the linkId
     * @param {object} options 
     * @returns {object} the status of an evtLink
     */
    async getStatusOfEvtLink(options) {
        if (typeof options !== "object" || !options) throw new Error("invalid options");
        if (!options.linkId || typeof options.linkId !== "string") throw new Error("invalid linkId");
        options = Object.assign({
            block: true,
            throwException: false
        }, options);

        let url;
        if (options.block) {
            url = "/v1/evt_link/get_trx_id_for_link_id";
        }
        else {
            url = "/v1/chain/get_trx_id_for_link_id";
        }

        let res, currentTime = new Date().valueOf();
        let lastTimeInternet = false, lastError = null;

        do {
            lastTimeInternet = false;
            res = undefined;
            try {
                res = await this.__callAPI({
                    url,
                    method: "POST",
                    body: { link_id: options.linkId },
                    sign: false // no need to sign
                });
            }
            catch (e) {
                if (!options.block && options.throwException) {
                    throw e;
                }
                else {
                    if (e.isServerError) {
                        lastTimeInternet = true;
                    }
                    lastError = e;
                }
            }

            if (res && res.trx_id) {
                lastTimeInternet = true;
                return { pending: false, successful: true, transactionId: res.trx_id, blockNum: res.block_num };
            }
            else {
                if (res && res.error) {
                    lastTimeInternet = true;

                    if (options.throwException && !options.block) {
                        this.__throwServerResponseError(res);
                    }
                    else {
                        try {
                            this.__throwServerResponseError(res);
                        }
                        catch (e) {
                            if (e.isServerError) {
                                lastTimeInternet = true;
                            }
                            if (!options.block)
                                return { pending: true, successful: false, exception: e };
    
                            lastError = e;
                        }
                    }
                }
                // else: the error is handled already in last catch block
            }
        }
        while (new Date().valueOf() - currentTime < 15000 && options.block)

        if (lastTimeInternet) {
            return { pending: false, successful: false, exception: lastError || new Error("everiPay timeOut or network issue") };
        }
        else {
            return { pending: true, successful: false, exception: new Error("No available network connection") };
        }
    }

    /**
     * Get a raw transaction but does NOT push it to the blockchain
     */
    async generateUnsignedTransaction() {
        /** @type Array */
        let args = [].slice.call(arguments);
        if (args.length == 0) throw new Error("invalid arguments");
        if (args[0] instanceof EvtAction) {
            args = [ { } ].concat(args);
        }

        args[0].__estimateCharge = true;

        let p = await this.pushTransaction.apply(this, args);

        return { transaction: p.body.transaction };
    }

    /**
     * Get estimated charge for a transaction
     */
    async getEstimatedChargeForTransaction() {
        /** @type Array */
        let args = [].slice.call(arguments);
        if (args.length == 0) throw new Error("invalid arguments");
        if (args[0] instanceof EvtAction) {
            args = [ { } ].concat(args);
        }

        args[0].__estimateCharge = true;

        let p = await this.pushTransaction.apply(this, args);

        // Get required keys
        Logger.verbose("[getEstimatedChargeForTransaction] get required_keys, available keys: " + JSON.stringify(p.publicKeys, null, 4));
        let apiRes = await this.__chainGetRequiredKeys({ transaction: p.body.transaction, available_keys: p.publicKeys });
        let required_keys = apiRes.required_keys;

        Logger.verbose("[getEstimatedChargeForTransaction] got required_keys: " + JSON.stringify(required_keys, null, 4));

        let res = await this.__callAPI({
            url: "/v1/chain/get_charge",
            method: "POST",
            body: { transaction: p.body.transaction, sigs_num: required_keys.length },
            sign: false // no need to sign
        });
 
        if (res && res.charge !== undefined) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * get detail information about a domain by its name. Make sure you have history_plugin enabled on the chain node
     * @param {*} name the name of the domain
     */
    async getDomainDetail(name) {
        if (typeof name !== "string" || !name) throw new Error("invalid domain name");

        let res = await this.__callAPI({
            url: "/v1/evt/get_domain",
            method: "POST",
            body: { name },
            sign: false // no need to sign
        });

        if (res && res.name && res.creator) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * Fetch all the transaction ids in one block
     * @param {string} blockId the id of the block
     */
    async getTransactionIdsInBlock(blockId) {
        if (typeof blockId !== "string" || !blockId) throw new Error("invalid blockId");
        if (blockId.length < 64) throw new Error("invalid blockId. Note: block id is not the same as block num.");

        let res = await this.__callAPI({
            url: "/v1/chain/get_transaction_ids_for_block",
            method: "POST",
            body: { block_id: blockId },
            sign: false // no need to sign
        });

        if (res && Array.isArray(res)) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * get balances of a user's all kinds of fungible tokens. Make sure you have history_plugin enabled on the chain node
     * @param {string} address the public key of the user you want to query
     * @param {number} symbolId the symbol you want to query, optional
     */
    async getFungibleBalance(address, symbolId) {
        if (typeof address !== "string" || !address) throw new Error("invalid address");

        //if (!this.__cachedInfo) {
        await this.getInfo();
        //}

        // If the version is lower than 2.2 (including), then user old API, else use the new API
        let isNewerVersion = true;
        if (this.__cachedInfo.evt_api_version.startsWith("3.")) {
            isNewerVersion = false;
        }

        let body;
        
        if (symbolId || !isNewerVersion) {
            body = {
                address
            };
        }
        else {
            body = {
                addr: address
            };
        }

        if (symbolId) {
            body.sym_id = symbolId;

            if (!Number.isInteger(body.sym_id)) {
                throw new Error("sym_id must be integer");
            }
        }
        else {
            if (isNewerVersion && !this.__node_history_plugin_enabled) {
                throw new Error("calling getFungibleBalance without symbolId parameter is only supported when history plugin is eneabled on the connected node if evt api version >= 4.0");
            }
        }

        let args = {
            url: isNewerVersion && !symbolId ? "/v1/history/get_fungibles_balance" : "/v1/evt/get_fungible_balance",
            method: "POST",
            body,
            sign: false // no need to sign
        };
        
        //console.log("[args]!!!!!!!!!!");

        //console.log(args); // For Test Only, TODO

        let res = await this.__callAPI(args);

        // console.log(res);

        if (res && Array.isArray(res)) {
            return res;
        } 
        if (res && (typeof res === "string")) {
            return [ res ];
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * get detail information about a group by its name. Make sure you have history_plugin enabled on the chain node
     * @param {*} name the name of the group
     */
    async getGroupDetail(name) {
        if (typeof name !== "string" || !name) throw new Error("invalid group name");

        let res = await this.__callAPI({
            url: "/v1/evt/get_group",
            method: "POST",
            body: { name },
            sign: false // no need to sign
        });

        if (res && res.name && res.root) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * Query fungible actions by address
     * @param {number} symbolId the id of the symbol 
     * @param {string} address the address (optional)
     * @param {number} skip the count to be skipped, default to 0 (optional)
     * @param {number} take the count to be taked, default to 10 (optional)
     */
    async getFungibleActionsByAddress(symbolId, address = undefined, skip = 0, take = 10) {
        if (!symbolId) throw new Error("invalid symbolId");
        // if (!address) throw new Error("invalid address");

        skip = skip || 0;
        take = take || 10;

        if (!address) {
            address = undefined;
        }

        let body = {
            sym_id: symbolId,
            addr: address,
            skip,
            take
        };

        let res = await this.__callAPI({
            url: "/v1/history/get_fungible_actions",
            method: "POST",
            body: body,
            sign: false // no need to sign
        });

        if (Array.isArray(res)) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * get detail information about transactions which involves specific public keys. Make sure you have history_plugin enabled on the chain node
     * @param {string[]} publicKeys a single value or a array of public keys to query (required)
     * @param {number} skip the count to be skipped, default to 0 (optional)
     * @param {number} take the count to be taked, default to 10 (optional)
     * @param {string} direction the direction for sorting the result. Defaults to `desc`. Could only be one of "desc" or "asc". (optional)
     */
    async getTransactionsDetailOfPublicKeys(publicKeys, skip = 0, take = 10, direction = "desc") {
        if (!publicKeys) throw new Error("invalid publicKeys");
        if (!Array.isArray(publicKeys)) {
            publicKeys = [ publicKeys ];
        }
        if (!direction) {
            direction = "desc";
        }
        if (direction !== "desc" && direction !== "asc") {
            throw new Error("parameter `direction` could only be one of `desc` or `asc`, but `" + direction + "` given" );
        }

        skip = skip || 0;
        take = take || 10;

        let body = {
            keys: publicKeys,
            skip,
            take,
            dire: direction
        };

        let res = await this.__callAPI({
            url: "/v1/history/get_transactions",
            method: "POST",
            body: body,
            sign: false // no need to sign
        });

        // fix backend bug: for empty dataset, remove quote
        if (res == "[]") {
            return [ ]; // tricky bug fix TODO
        }
        else if (Array.isArray(res)) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * get detail information about a fungible symbol by its name.
     * @param {Number} id the id of the fungible symbol you want to query
     */
    async getFungibleSymbolDetail(id) {
        if (!Number.isInteger(id)) throw new Error("fungible id should has a type of number");

        let res = await this.__callAPI({
            url: "/v1/evt/get_fungible",
            method: "POST",
            body: { id },
            sign: false // no need to sign
        });

        if (res && res.sym && res.creator) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * Get header state of head block.
     */
    async getHeadBlockHeaderState() {
        let res = await this.__callAPI({
            url: "/v1/chain/get_head_block_header_state",
            method: "GET",
            sign: false // no need to sign
        });

        if (!res.error) {
            return res;
        }
        else {
            this.__throwServerResponseError(res);
        }
    }

    /**
     * wrap the exception returned from server side
     * @param {*} res 
     */
    __throwServerResponseError(res) {
        let details = "";

        if (res.error && res.error.details && Array.isArray(res.error.details)) {
            for (let detail of res.error.details) {
                details += `\nat ${detail.file}::${detail.method}: ${detail.message} (line ${detail.line_number})`;
            }
        }

        let err = new Error(`[${res.code} ${res.message}] (${(res.error || {}).code}) ${(res.error || {}).name}: ${(res.error || {}).what} ${details}`);
        err.httpCode = res.code;
        err.serverError = res.error;
        err.serverMessage = res.message;
        err.rawServerError = res;
        err.isServerError = true;

        Logger.verbose("[__throwServerResponseError] node's response return error:\n" + JSON.stringify(res, null, 4));

        throw err;
    }

    /**
     * Calculate the value of keyProvider
     * @param {string | string[] | function} keyProvider
     * @returns {string[]}
     */
    async __calcKeyProvider(keyProvider, trx) {
        if (!keyProvider) { return []; }

        // if keyProvider is function
        if (keyProvider.apply && keyProvider.call) {
            keyProvider = keyProvider( { transaction: trx });
        }

        // resolve for Promise
        keyProvider = await Promise.resolve(keyProvider);

        if (!Array.isArray(keyProvider)) {
            keyProvider = [ keyProvider ];
        }

        for (let key of keyProvider) {
            if (!EvtKey.isValidPrivateKey(key)) {
                throw new Error("Invalid private key");
            }
        }

        return keyProvider;
    }

    /**
     * Calculate the value of publicKeyProvider
     * @param {string | string[] | function} keyProvider
     * @returns {string[]}
     */
    async __calcPublicKeyProvider(keyProvider) {
        if (!keyProvider) { return []; }

        // if keyProvider is function
        if (keyProvider.apply && keyProvider.call) {
            keyProvider = keyProvider();
        }

        // resolve for Promise
        keyProvider = await Promise.resolve(keyProvider);

        if (!Array.isArray(keyProvider)) {
            keyProvider = [ keyProvider ];
        }

        for (let key of keyProvider) {
            if (!EvtKey.isValidPublicKey(key)) {
                throw new Error("Invalid public key");
            }
        }

        return keyProvider;
    }

    /**
     * push transaction to everiToken chain
     * @param {[config{}], any[]} actions actions in the transaction
     * if config.submitToNode is set to false, the return would be a signed transaction with config.
     * if config.AbiJsonToBinLocally is set to true, the binargs would be calculated natively.
     */
    async pushTransaction() {
        let actions = [ ];
        let rawActions = [];
        let hasConfig = false;

        // default config
        let trxConf = {
            maxCharge: 100000000,
            submitToNode: true,
            AbiJsonToBinLocally: false
        };

        // check and copy config from parameters
        if (arguments.length > 0 && !(arguments[0] instanceof EvtAction) && !arguments[0].action) {
            // config found
            Object.assign(trxConf, arguments[0]);
            hasConfig = true;
        }

        // calculate and cache private keys
        let privateKeys = [];
        let publicKeys = [];

        // user can use availablePublicKeys in config for estimate, or use keyProvider instead
        if (!trxConf.__estimateCharge || !trxConf.availablePublicKeys) {
            privateKeys = await this.__calcKeyProvider(this.config.keyProvider, null);
            publicKeys = privateKeys.map(x => EvtKey.privateToPublic(x));
        }
        else {
            publicKeys = await this.__calcPublicKeyProvider(trxConf.availablePublicKeys);
        }

        // set default payer if user provided only one private key
        if (!trxConf.payer && privateKeys.length == 1) {
            trxConf.payer = EvtKey.privateToPublic(privateKeys[0]);
        }
        
        for (let i = (hasConfig ? 1 : 0); i < arguments.length; ++i) {
            actions.push(arguments[i]);
        }

        rawActions = actions.slice();

        // check arguments
        if (actions.length == 0) {
            throw new Error("At least 1 action needed");
        }
        if (trxConf.maxCharge == null || !Number.isInteger(trxConf.maxCharge)) throw new Error("maxCharge is required and must be a integer greater than or eqaul to 0");
        if (!trxConf.__estimateCharge && (trxConf.payer == null || !EvtKey.isValidAddress(trxConf.payer))) throw new Error("payer is required and must be a valid address as a string");

        let params = {
            transaction: {
                actions: actions
            }
        };
        // check arguments
        if (!params.transaction) {
            throw new Error("invalid format of params: no transaction field");
        }

        params.sign = params.sign !== false ? true : false;

        // building the body of the request
        let body = { transaction: params.transaction };

        // make sure that it there is basic information about the chain
        // because we need some information from getInfo and the information will be expired after some time
        // so at the time being we will call getInfo eachtime we push a transaction
        // It can not be changed to do in cycle because node split some information into sections
        // and you can't guess when it will be expired
        await this.getInfo();

        for (let i = 0; i < body.transaction.actions.length; ++i) {
            if (!(body.transaction.actions[i] instanceof EvtAction)) {
                body.transaction.actions[i] = new EvtAction(body.transaction.actions[i].action, body.transaction.actions[i].args);
            }

            await body.transaction.actions[i].calculateDomainAndKey();

            /** @type {EvtAction} */
            let originalAction = body.transaction.actions[i];

            // create binary action for push_transaction
            let binAction = {
                name: originalAction.actionName,
                data: (await this.__chainAbiJsonToBin({ action: originalAction.actionName, args: originalAction.abi }, trxConf.AbiJsonToBinLocally)).binargs,
                domain: originalAction.domain,
                key: originalAction.key
            };

            // if everiPay is included, expiration is not supported
            if (binAction.name == "everipay") {
                trxConf.__hasEveriPay = true;
                trxConf.__linkId = (await EvtLink.parseEvtLink(originalAction.abi.link)).segments.filter(x => x.typeKey == 156)[0].value.toString("hex")

                if (trxConf.expiration) {
                    throw new Error("Expiration can not be set in a transaction including a everipay action, the expiration must be set automatically by evtjs");
                }
            }
            
            // override action
            body.transaction.actions[i] = binAction;
        }

        let expiration, hash, numHex, last_irreversible_block_num, last_irreversible_block_prefix;

        // process referenced block number and expiration time for transaction
        if (trxConf.expiration) {
            expiration = trxConf.expiration;
        }
        else {
            if (trxConf.__hasEveriPay) {
                // for everiPay, only 10s is allowed for expiration
                expiration = new Date(await this.getNodeTimestamp() + 10000).toISOString().substr(0, 19);
            }
            else {
                expiration = new Date(await this.getNodeTimestamp() + 100000).toISOString().substr(0, 19);
            }
        }
        
        hash = ByteBuffer.fromHex(this.__cachedInfo.last_irreversible_block_id, true); // little endian
        numHex = this.__cachedInfo.last_irreversible_block_id.substr(4, 4);
        last_irreversible_block_num = ByteBuffer.fromHex(numHex, false).readUint16(0);
        last_irreversible_block_prefix = hash.readUInt32(8);

        body = Object.assign(body, {
            compression: "none"
        });

        body.transaction = Object.assign(body.transaction, {
            "expiration": expiration,
            "ref_block_num": last_irreversible_block_num,
            "ref_block_prefix": last_irreversible_block_prefix
        });

        // add payer and maxCharge to the transaction
        body.transaction.max_charge = trxConf.maxCharge;
        body.transaction.payer = trxConf.payer;

        if (trxConf.__estimateCharge) {
            return { body, publicKeys };
        }

        // calculate signatures
        if (params.sign) {
            // get digest of the whole trx
            let digestRes = (await this.__getDigestToSign(body.transaction)).digest;

            // sign
            const signBuf = new Buffer(digestRes, "hex");
            let sigs = await this.__signTransaction(signBuf, body.transaction, privateKeys, rawActions);

            if (!Array.isArray(sigs)) {
                sigs = [ sigs ];
            }
            
            body.signatures = sigs;
        }

        // if not setting to push, abort and return body (with signature)
        if (!trxConf.submitToNode) {
            return {
                body,
                config: trxConf
            }; // return transaction with full signature
        }

        // push transaction
        // console.log("__body:" + JSON.stringify(body, null, 4));
        return (await this.pushSignedTransaction(body, trxConf.__hasEveriPay ? trxConf.__linkId : null));
        
    }

    /**
     * push a signed transaction
     * @param {string} body 
     * @param {trxConf.__linkId} includedEvtLinkID 
     */
    async pushSignedTransaction(body, includedEvtLinkID=null) {

        var res = await this.__chainPushTransaction(body);

        // check if it is successful
        if (includedEvtLinkID !== null) {
            // For everiPay transaction, for safety, use strict mode
            let ret = await this.getStatusOfEvtLink({ linkId: includedEvtLinkID, block: true, throwException: false });

            if (ret && ret.pending == false && ret.successful && ret.transactionId) {
                return { transactionId: ret.transactionId };
            }
            else {
                throw ret.exception || new Error("transaction is timeout");
            }
        }
        else if (res && res.processed && res.processed.receipt && res.processed.receipt.status === "executed") {
            return { transactionId: res.transaction_id, charge: res.processed.charge, body };
        }
        else {
            // throw error detail
            if (res && res.error && res.error.details && res.error.details.length) {
                this.__throwServerResponseError(res);
            }
            else {
                throw new Error("did not receive anything from the chain");
            }
        }
    }

    async __chainAbiJsonToBinByAPI(abi) {
        let ret = await this.__callAPI({
            url: "/v1/chain/abi_json_to_bin",
            method: "POST",
            body: abi
        });

        if (ret.binargs) return ret;
        else this.__throwServerResponseError(ret);
    }

    async __chainAbiJsonToBinByFC(abi) {
        if (structs.structs[abi.action]) {
            let obj = structs.structs[abi.action].fromObject(abi.args);
            let bin = Fcbuffer.toBuffer(structs.structs[abi.action], obj);
            return { binargs: bin.toString("hex") };
        } else {
            return await this.__chainAbiJsonToBinByAPI(abi);
            // this.__throwServerResponseError("Unknown Action");
        }
        
    }
    
    async __chainAbiJsonToBin(abi, AbiJsonToBinLocally=false) {
        if (!AbiJsonToBinLocally) return await this.__chainAbiJsonToBinByAPI(abi);
        else return await this.__chainAbiJsonToBinByFC(abi);
    }

    /**
     * 
     * @param {Buffer} buf 
     * @param {object} transaction 
     * @param {string[]} privateKeys 
     */
    __signTransaction(buf, transaction, privateKeys, actions) {
        return this.config.signProvider({signHash, buf, transaction, privateKeys, actions});
    }

    async __getDigestToSign(transaction) { 
        let ret = null;
        try {
            ret = await this.__callAPI({
                url: "/v1/chain/trx_json_to_digest",
                method: "POST",
                body: transaction
            });
        }
        catch (e) {
            // console.log("[__getDigestToSign] trx: \n" + JSON.stringify(transaction, null, 4));
            throw e;
        }

        if (ret && ret.digest) {
            return ret;
        }

        this.__throwServerResponseError(ret);
    }

    __chainPushTransaction(tr) {
        // console.log("___push_:::" + JSON.stringify(tr, null, 4));
        return this.__callAPI({
            url: "/v1/chain/push_transaction",
            method: "POST",
            body: tr
        });
    }

    __chainGetRequiredKeys(body) {
        return this.__callAPI({
            url: "/v1/chain/get_required_keys",
            method: "POST",
            body
        });
    }
}

/**
  The default sign provider is designed to interact with the available public
  keys (maybe just one), the transaction, and the blockchain to figure out
  the minimum set of signing keys.

  If only one key is available, the blockchain API calls are skipped and that
  key is used to sign the transaction.
*/
const defaultSignProvider = (apiCaller, config) => async function ({ signHash, buf, transaction, privateKeys }) {
    let keys = privateKeys;

    if (!keys) {
        throw new TypeError("This transaction requires keyProvider for signing, please check your initial parameter of APICaller class.");
    }

    keys = keys.map(key => {
        return {
            private: ecc.PrivateKey(key).toString(),
            public: EvtKey.privateToPublic(ecc.PrivateKey(key).toString())
        };
    });

    if (!keys.length) {
        throw new Error("missing key, check your keyProvider");
    }

    // simplify default signing #17
    if (keys.length === 1 && keys[0].private) {
        const pvt = keys[0].private;
        var ret = await signHash(buf, pvt);
        
        return ret;
    }

    // Multiple signature support
    Logger.verbose("[defaultSignProvider] get required_keys, available keys: " + JSON.stringify(keys.map(key => key.public ), null, 4));
    let apiRes = await apiCaller.__chainGetRequiredKeys({ transaction, available_keys: keys.map(key => key.public ) });
    let required_keys = apiRes.required_keys;

    Logger.verbose("[defaultSignProvider] got required_keys: " + JSON.stringify(apiRes, null, 4));

    const pvts = [], missingKeys = [];

    for (let requiredKey of required_keys) {
        let wifs = keys.filter(x => x.public == requiredKey);

        if (wifs.length == 1) {
            pvts.push(wifs[0].private);
        } else {
            missingKeys.push(requiredKey);
        }
    }

    if (missingKeys.length !== 0) {
        throw new Error("missingKeys for required_key");

        // const pubkeys = missingKeys.map(key => ecc.PublicKey(key).toStringLegacy())
        //keyProvider({ pubkeys: missingKeys })
        //    .forEach(pvt => { pvts.push(pvt); });
    }

    const sigs = [];
    for (const pvt of pvts) {
        sigs.push(await signHash(buf, pvt));
    }

    return sigs;
    //})
};

module.exports = { APICaller };
