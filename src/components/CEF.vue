<template>
  <div class="cef">
    <table id="ceftable">
      <tr class="header">
        <th>Field</th>
        <th>Value</th>
        <th class="comment">Comment<button class="right" v-on:click="copyToClipboard('ceftable')">Copy to
            clipboard</button>
        </th>
      </tr>
      <tr class="section">
        <th colspan="3">Input</th>
      </tr>
      <tr class="raw">
        <th>Raw</th>
        <td>
          <pre>{{ message }}</pre>
        </td>
        <td></td>
      </tr>
      <template v-if="cef.Version">
        <tr class="section">
          <th colspan="3">CEF Header</th>
        </tr>
        <tr class="cefheader">
          <th>Version</th>
          <td>
            <pre>{{ cef.Version }}</pre>
          </td>
          <td></td>
        </tr>
        <tr class="cefheader">
          <th>DeviceVendor</th>
          <td>
            <pre>{{ cef.DeviceVendor }}</pre>
          </td>
          <td></td>
        </tr>
        <tr class="cefheader">
          <th>DeviceProduct</th>
          <td>
            <pre>{{ cef.DeviceProduct }}</pre>
          </td>
          <td></td>
        </tr>
        <tr class="cefheader">
          <th>DeviceVersion</th>
          <td>
            <pre>{{ cef.DeviceVersion }}</pre>
          </td>
          <td></td>
        </tr>
        <tr class="cefheader">
          <th>SignatureID</th>
          <td>
            <pre>{{ cef.SignatureID }}</pre>
          </td>
          <td></td>
        </tr>
        <tr class="cefheader">
          <th>Name</th>
          <td>
            <pre>{{ cef.Name }}</pre>
          </td>
          <td></td>
        </tr>
        <tr class="cefheader">
          <th>Severity</th>
          <td>
            <pre>{{ cef.Severity }}</pre>
          </td>
          <td></td>
        </tr>
      </template>
      <tr class="section" v-if="cef.extensionsSorted.length > 0">
        <th colspan="3">CEF Extensions</th>
      </tr>
      <tr class="cefextension" v-for="ext in cef.extensionsSorted" :key="ext.key">
        <th :title="ext.meta.fullName" :class="ext.meta.invalidExtensionName && 'status_warning'">{{ ext.key }}</th>
        <td :class="ext.meta.invalidValue && 'status_warning'">
          <pre>{{ ext.value | pretty() }}</pre>
        </td>
        <td>
          <ul>
            <li v-for="comment in ext.comments" :key="comment">{{ comment }}</li>
            <li v-for="error in ext.errors" :key="error" class="status_error">{{ error }}</li>
            <li v-for="warning in ext.warnings" :key="warning" class="status_warning">{{ warning }}</li>
            <li v-for="notice in ext.notices" :key="notice" class="status_notice">{{ notice }}</li>
            <li class="status_notice"
              v-if="(ext.key == 'rt' || ext.key == 'start' || ext.key == 'end' || ext.key == 'art' || ext.key == 'deviceCustomDate1') && /^[0-9]+$/.test(ext.value)">
              {{ (new Date(Number(ext.value))).toISOString() }}</li>
          </ul>
        </td>
      </tr>
      <tr class="section" v-if="cef.extensionsByLabelSorted.length > 0">
        <th colspan="3">CEF Extensions by Label</th>
      </tr>
      <tr class="cefextension" v-for="ext in cef.extensionsByLabelSorted" :key="ext.key">
        <th>{{ ext.key }}</th>
        <td>
          <pre>{{ ext.value }}</pre>
        </td>
        <td></td>
      </tr>
    </table>
  </div>
</template>

<script>

// include extension dictionary at build time
import DICTIONARY from './extension-dictionary.json'

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

  // search for CEF message prefix
  var i = this.search(/CEF:/);
  if (i == -1) {
    // CEF prefix not found
    return obj;
  } else {
    i += 4; // skip CEF prefix
  }

  // Header
  var field = 0;
  var startHeader = i; // start of header value
  var quoted = false;
  Header: while (i < this.length) {
    switch (this[i]) {
      case "|": // field separator
        if (quoted) {
          obj[cefHeaders[field]] = this.substring(
            startHeader, i).unescapeCefValue();
          quoted = false;
        } else {
          obj[cefHeaders[field]] = this.substring(
            startHeader, i);
        }
        i++;
        startHeader = i;
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
    if (quoted) {
      obj[cefHeaders[field]] = this.substring(
        startHeader, i).unescapeCefValue();
      quoted = false;
    } else {
      obj[cefHeaders[field]] = this.substring(
        startHeader, i);
    }

    return obj;
  }

  // Extensions
  var key = "";
  var startKeyValuePair = i; // start position of a key-value pair
  var startValue; // start position of a value
  var foundfirstKeyValueSeparator = false; // are we looking for the first key-value pair
  while (i < this.length) {
    switch (this[i]) {
      case " ": // keypair separator
        i++;
        // note possible start of new key pair
        startKeyValuePair = i;
        break;
      case "=": // key-value separator
        if (!foundfirstKeyValueSeparator) {
          // first key-value separator found, just note key
          foundfirstKeyValueSeparator = true;
        } else {
          // on subsequent key-value separators, we know where the previous value ended and add the previous key-value pair to extensions
          if (quoted) {
            obj.extensions[key] = this
              .substring(startValue, startKeyValuePair - 1).unescapeCefValue();
            quoted = false;
          } else {
            obj.extensions[key] = this
              .substring(startValue, startKeyValuePair - 1);
          }
        }

        key = this.substring(startKeyValuePair, i);
        // empty key
        // if (key == "")
        //     return null;

        i++;
        startValue = i;
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
  if (foundfirstKeyValueSeparator) {
    if (quoted) {
      obj.extensions[key] = this.substring(startValue, i).unescapeCefValue();
    } else {
      obj.extensions[key] = this.substring(startValue, i);
    }
  }

  return obj;
};

function validateExtensionValue(name, dataType, length, value) {
  switch (dataType) {
    case "String":
      if (value.length > length) {
        return "Length of " + value.length + " exceeds limit of " + length;
      }
      break;
    case "Time Stamp":
      console.log("Unvalidated dataType: %s", dataType);
      break;
    case "MAC Address":
      if (!/^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$/.test(value)) {
        return "Invalid format";
      }
      break;
    case "IPv4 Address":
    case "IPv6 Address":
    case "IP Address":
      console.log("Unvalidated dataType: %s", dataType);
      break;
    case "Integer": {
      const n = parseInt(value);
      if (Number.isNaN(n) || n > 2147483647 || n < -2147483648) {
        return "Invalid Integer";
      }
      break;
    }
    case "Long": {
      try {
        const n = BigInt(value);
        if (n > 922337203685477580n || n < -9223372036854775808n) {
          return "Invalid Long";
        }
      } catch (error) {
        return "Invalid Long";
      }
      break;
    }
    default:
      return ("Unknown dataType: " + dataType);
  }

  if (/host$/i.test(name)) {
    if (!/^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$/igm.test(value)) {
      return "Invalid FQDN";
    }
  }
  return true;
}

function capitalizeFirstLetter(string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
}

function prepareCefDisplay(cef, dictionary) {
  cef.extensionsSorted = Object.entries(cef.extensions).
    // convert object to sorted array of objects
    map(([k, v]) => {
      let obj = { "key": k, "meta": {}, "comments": [], "errors": [], "warnings": [], "notices": [] };

      // mixin meta data from dictionary
      if (k in dictionary) {
        Object.assign(obj.meta, dictionary[k]);

        obj.comments.push(dictionary[k]["fullName"]);
        if (dictionary[k]["dictionaryName"] == "consumer") {
          obj.notices.push(capitalizeFirstLetter(dictionary[k]["dictionaryName"]) + " extension from CEF specification " + dictionary[k]["version"]);
        } else {
          obj.comments.push(capitalizeFirstLetter(dictionary[k]["dictionaryName"]) + " extension from CEF specification " + dictionary[k]["version"]);
        }
        obj.comments.push(dictionary[k]["dataType"] + (dictionary[k]["length"] ? "[" + dictionary[k]["length"] + "]" : ""));
        let validity = validateExtensionValue(k, dictionary[k]["dataType"], dictionary[k]["length"], v);
        if (validity !== true) {
          obj.meta["invalidValue"] = true;
          obj.warnings.push(validity);
        }
        obj.comments.push(dictionary[k]["description"]);
      } else {
        obj.meta["userDefinedExtension"] = true;
        obj.comments.push("User-Defined Extension");
        if (!/^[A-Z][a-zA-Z0-9]*$/.test(k)) {
          // https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/cef-implementation-standard/index.html#CEF/Chapter%204%20User%20Defined%20Extensions.htm#Limitations?TocPath=_____5
          obj.meta["invalidExtensionName"] = true;
          obj.warnings.push("Extension name does not adhere to VendornameProductnameExplanatoryKeyName format");
        }
      }

      // try to parse value as JSON
      if (typeof v === "string" && (v.startsWith('{') || v.startsWith('"'))) {
        try {
          v = JSON.parse(v);
          obj.meta["contentType"] = "json";
          // try to parse embedded JSON
          if (typeof v === "string" && v.startsWith('{')) {
            try {
              v = JSON.parse(v);
              obj.notices.push("Pretty print embedded JSON");
              obj.meta["contentType"] = "embedded-json";
            } catch (err) {
              console.error("Failed to parse '%s' extension value as embedded JSON.", k, err)
            }
          } else {
            obj.notices.push("Pretty print JSON");
          }
        } catch (err) {
          console.error("Failed to parse '%s' extension value as JSON.", k, err)
        }
      }
      obj["value"] = v;

      return obj;
    }).
    // sort by "key" property
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

  // add keypair for c[ns]<i>Label with value c[ns]<i>
  cef.extensionsByLabel = {};
  for (var key in cef.extensions) {
    if (/Label$/.test(key)) {
      var baseKey = key.slice(0, -5);
      if (baseKey in cef.extensions) {
        cef.extensionsByLabel[cef.extensions[key]] = cef.extensions[baseKey];
      }
    }
  }

  // convert object to sorted array of objects
  cef.extensionsByLabelSorted = Object.entries(cef.extensionsByLabel).
    map(([k, v]) => ({ "key": k, "value": v })).
    // sort by "key" property
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

  return cef;
}

export default {
  name: 'CEF',
  props: {
    message: String
  },
  computed: {
    cef: function () {
      return prepareCefDisplay(this.message.parseCEF(), DICTIONARY);
    }
  },
  methods: {
    copyToClipboard(containerid) {
      const containerNode = document.getElementById(containerid);
      const range = document.createRange();
      range.selectNode(containerNode);
      window.getSelection().removeAllRanges();
      window.getSelection().addRange(range);
      document.execCommand("copy");
      window.getSelection().removeAllRanges();
      console.log("Table copied to clipboard");
    }
  },
  filters: {
    // pretty print objects
    pretty: (val, indent = 2) => {
      if (typeof val !== "string") {
        return JSON.stringify(val, null, indent);
      } else {
        return val;
      }
    }
  }

}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
table {
  margin-top: 2em;
  width: 100%;
  border-collapse: collapse;
}

td,
th {
  border: 1px solid #ddd;
  padding-left: 8px;
  padding-right: 8px;
  padding-top: 3px;
  padding-bottom: 3px;
  text-align: left;
  vertical-align: top;
}

.status_error {
  font-weight: bold;
  color: #E5004C;
}

.status_warning {
  font-weight: bold;
  color: #F48B34;
}

.status_notice {
  font-weight: bold;
  /* color: #FCDB1F; */
}

tr:hover {
  background-color: #ddd;
}

tr.header th {
  padding-top: 12px;
  padding-bottom: 12px;
  background-color: #0079ef;
  color: white;
}

tr.header th.comment {
  width: 30%;
}

tr.section th {
  padding-top: 8px;
  padding-bottom: 8px;
  background-color: #29cdfe;
  color: white;
}

button.right {
  float: right;
}

pre {
  white-space: pre-wrap;
  margin: 2px;
}

ul {
  margin-top: 0px;
  margin-bottom: 0px;
  padding-left: 16px;
}
</style>
