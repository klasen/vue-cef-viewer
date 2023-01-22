<template>
  <div class="cef">
    <table>
      <tr class="header">
        <th>Field</th>
        <th>Value</th>
        <th>Comment</th>
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
        <th>{{ ext.key }}</th>
        <td>
          <pre>{{ ext.value | pretty() }}</pre>
        </td>
        <td>
          <div
            v-if="(ext.key == 'rt' || ext.key == 'start' || ext.key == 'end' || ext.key == 'art' || ext.key == 'deviceCustomDate1') && /^[0-9]+$/.test(ext.value)">
            {{ (new Date(Number(ext.value))).toISOString() }}
          </div>
        </td>
      </tr>
      <tr class="section" v-if="cef.extensionsByLabelSorted.length > 0">
        <th colspan="3">CEF Extensions by Label</th>
      </tr>
      <tr class="cefextension" v-for="ext in cef.extensionsByLabelSorted" :key="ext.key">
        <th>{{ ext.key }}</th>
        <td>
          <pre>{{ ext.value | pretty() }}</pre>
        </td>
        <td></td>
      </tr>
    </table>
  </div>
</template>

<script>
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

function prepareCefDisplay(cef) {
  cef.extensionsSorted = Object.entries(cef.extensions).
    // object to array of objects
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

  // add keypair for c[ns]<i>Label with value c[ns]<i>
  cef.extensionsByLabel = {};
  for (var key in cef.extensions) {
    if (/Label$/.test(key)) {
      var baseKey = key.slice(0, -5);
      if (cef.extensions[baseKey]) {
        cef.extensionsByLabel[cef.extensions[key]] = cef.extensions[baseKey];
      }
    }
  }

  cef.extensionsByLabelSorted = Object.entries(cef.extensionsByLabel).
    // object to array of objects
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
      return prepareCefDisplay(this.message.parseCEF());
    }
  },
  filters: {
    // pretty print JSON
    pretty: (val, indent = 2) => {
      if (typeof val === "string") {
        try {
          val = JSON.parse(val);
        } catch (err) {
          return val;
        }
        // parse embedded JSON
        if (typeof val === "string") {
          console.debug("Decoding dembedded JSON", val)
          try {
            val = JSON.parse(val);
          } catch (err) {
            console.warn("Failed to decode embedded JSON", err)
          }
        }

        return JSON.stringify(val, null, indent);
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

tr:hover {
  background-color: #ddd;
}

tr.header th {
  padding-top: 12px;
  padding-bottom: 12px;
  background-color: #0079ef;
  color: white;
}

tr.section th {
  padding-top: 8px;
  padding-bottom: 8px;
  background-color: #29cdfe;
  color: white;
}

pre {
  white-space: pre-wrap;
  margin: 2px;
}
</style>
