
const cefHeaders = ['Version', 'DeviceVendor',
    'DeviceProduct', 'DeviceVersion', 'SignatureID', 'Name', 'Severity'
];

const cefValueEscapeRegex = /\\(.)/g;
const cefValueEscapeSequences = {
    'n': '\n',
    'r': '\r',
    't': '\t'
};

/**
 * Unescape string according to CEF Character Encoding rules
 * @return {string}
 */
String.prototype.unescapeCefValue = function () {
    return this.replace(cefValueEscapeRegex, (match, p1) => {
        if (p1 in cefValueEscapeSequences) {
            return cefValueEscapeSequences[p1];
        } else {
            return p1;
        }
    });
}

/**
* The parseCEF() function converts a string in CEF format into a hash where
* each value can be retrieved by its name. The following Header fields are
* available: Version, DeviceVendor, DeviceProduct, DeviceVersion, SignatureID,
* Name, and Severity. Key-value pairs from the Extension field of the message
* are made available under the extensions property.
* <p>
* Example:
* 
* <pre>
* var input='CEF:0|security|threatmanager|1.0|100|detected an equal sign ("=") in extension value|10|src=10.0.0.1 act=blocked a equal \\= dst=1.1.1.1'
* var cef = input.parseCEF();
* //result:
* {
*   &quot;extensions&quot;: {
*     &quot;src&quot;: &quot;10.0.0.1&quot;,
*     &quot;act&quot;: &quot;blocked a equal =&quot;,
*     &quot;dst&quot;: &quot;1.1.1.1&quot;
*   },
*   &quot;Version&quot;: &quot;0&quot;,
*   &quot;DeviceVendor&quot;: &quot;security&quot;,
*   &quot;DeviceProduct&quot;: &quot;threatmanager&quot;,
*   &quot;DeviceVersion&quot;: &quot;1.0&quot;,
*   &quot;SignatureID&quot;: &quot;100&quot;,
*   &quot;Name&quot;: &quot;detected a equal = in message&quot;,
*   &quot;Severity&quot;: &quot;10&quot;
* }
* </pre>
* 
* @addon
* @return {Object} Map of names (attributes) to values
*/
String.prototype.parseCEF = function () {
    var obj = {};
    obj.extensions = {};

    // search for start of a CEF message
    var i = this.search(/CEF:[0-9]/);
    if (i == -1) {
        // CEF prefix not found
        return obj;
    } else {
        i += 4; // skip CEF prefix
    }

    // Header
    var field = 0;
    var start = i; // start of header value
    var quoted = false;
    Header: while (i < this.length) {
        switch (this[i]) {
            case "|": // field separator
                if (quoted) {
                    obj[cefHeaders[field]] = this.substring(
                        start, i).unescapeCefValue();
                    quoted = false;
                } else {
                    obj[cefHeaders[field]] = this.substring(
                        start, i);
                }
                i++;
                start = i;
                field++;
                if (field == cefHeaders.length)
                    // all header fields have been parsed
                    break Header;
                break;
            case "\\": // quote char
                // note that value contains quote chars and needs special treatment
                quoted = true;
                // skip over quoted char
                i += 2;
                break;
            default:
                i++;
        }
    }
    if (field != cefHeaders.length) {
        // not enough header fields
        return obj;
    }

    // Extensions
    var key = "";
    // var start = i; // start position of key pair
    var value_start; // start position of value
    var first_kp = true; // are we looking for the first key pair
    while (i < this.length) {
        switch (this[i]) {
            case " ": // keypair separator
                i++;
                // note possible start of new key pair
                start = i;
                break;
            case "=": // key-value separator
                if (first_kp) {
                    // first key-value separator found, just note key
                    first_kp = false;
                } else {
                    // on subsequent key-value separators, we know where the previous value ended and add the previous key pair to extensions
                    if (quoted) {
                        obj.extensions[key] = this
                            .substring(value_start, start - 1).unescapeCefValue();
                        quoted = false;
                    } else {
                        obj.extensions[key] = this
                            .substring(value_start, start - 1);
                    }
                }

                key = this.substring(start, i);
                // empty key
                // if (key == "")
                //     return null;

                i++;
                value_start = i;
                break;
            case "\\": // quote char
                // >99% of data has no quotes, so take a note and call unescape on the full value later
                // this avoids having to reassemble string values without quotes in them
                quoted = true;
                i += 2;
                break;
            default:
                i++;
        }
    }
    // add last key pair to extensions
    if (quoted) {
        obj.extensions[key] = this.substring(value_start, i).unescapeCefValue();
    } else {
        obj.extensions[key] = this.substring(value_start, i);
    }

    // add keypair for c[ns]<i>Label with value c[ns]<i>
    // for (key in obj.extensions) {
    // if ( /^(cn|cs|c6a|flex(Number|Date|String))\d+$/.test(key) &&
    // obj.extensions[key+"Label"]) {
    // obj.extensions[obj.extensions[key+"Label"]] = obj.extensions[key];
    // }
    // }

    return obj;
};




new Vue({
    el: '#app',
    mounted: function () {
        this.$nextTick(function () {
            this.$refs.message.focus();
        })
    },
    data: {
        message: "",
    },
    computed: {
        cef: function () {
            return this.message.parseCEF();
        },
        extensions: function () {
            // transform extentions object into array of objects sorted by "key" property
            return Object.entries(this.message.parseCEF().extensions).
                map(([k, v]) => ({ "key": k, "value": v })).
                sort((a, b) => {
                    if (a.key < b.key) {
                        return -1;
                    }
                    if (a.key > b.key) {
                        return 1;
                    }
                    return 0;
                }
                );
        }
    }
})