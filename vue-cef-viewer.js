/**
* The parseCEF() function converts a string in CEF format into a hash where
* each value can be retrieved by its name. The following Prefix fields are
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
* @return {Hash} Map of names (attributes) to values
*/
String.prototype.parseCEF = function () {
    var obj = {};
    obj.extensions = {};
    var i = this.search(/CEF:[0-9]/);
    if (i == -1) {
        // no CEF
        return obj;
    } else {
        i += 4; // skip tag
    }
    // Prefix
    var field = 0;
    var start = i;
    var quoted = false;
    Prefix: while (i < this.length) {
        switch (this[i]) {
            case "|": // field separator
                if (quoted) {
                    obj[String.prototype.parseCEF.prefix[field]] = this.substring(
                        start, i).unescapeCefValue();
                    quoted = false;
                } else {
                    obj[String.prototype.parseCEF.prefix[field]] = this.substring(
                        start, i);
                }
                i++;
                start = i;
                field++;
                if (field == String.prototype.parseCEF.prefix.length)
                    // all prefix fields have been parsed
                    break Prefix;
                break;
            case "\\": // quote char
                // note that value contains quote chars and needs special treatment
                quoted = true;
                // skip over quote char
                i += 2;
                break;
            default:
                i++;
        }
    }
    if (field != String.prototype.parseCEF.prefix.length)
        return obj;

    // Extensions
    var key = "";
    // var start = i; // start position of key
    var value_start; // start position of value
    var first_kp = true;
    while (i < this.length) {
        switch (this[i]) {
            case "\\": // quote char
                // >99% of data has no quotes
                quoted = true;
                i += 2;
                break;
            case "=": // key-value separator
                if (first_kp) {
                    // first key-value separator, just note key
                    first_kp = false;
                } else {
                    if (quoted) {
                        // TODO embedded new lines replace(/\\n/g, "\n")
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
            case " ": // keypair separator
                i++;
                start = i;
                break;
            default:
                i++;
        }
    }
    // add last keypair
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

const cefValueEscapeRegex = /\\(.)/g;
const cefValueEscapeSequences = {
    'n': '\n',
    'r': '\r',
    't': '\t'
};

String.prototype.unescapeCefValue = function () {
    return this.replace(cefValueEscapeRegex, (match, p1) => {
        if (p1 in cefValueEscapeSequences) {
        return cefValueEscapeSequences[p1];
        } else {
            return p1;
        }
    });
}

String.prototype.parseCEF.prefix = ['Version', 'DeviceVendor',
    'DeviceProduct', 'DeviceVersion', 'SignatureID', 'Name', 'Severity'
];


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