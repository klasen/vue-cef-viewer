# vue-cef-viewer

Parse a raw [Common Event Format](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.1/cef-implementation-standard/) (CEF) log message and show it in a tabular view using [Vue.js](https://vuejs.org/).

Performs the following validations:

- User-defined extension name format
- String length
- Integer value range
- Long value range
- MAC Address format
- IPv4 and IPv6 format

Try it online at <https://klasen.github.io/vue-cef-viewer/>.

## Sample

<table id="ceftable">
    <tr class="header">
        <th>Field</th>
        <th>Value</th>
        <th class="comment">Comment</th>
    </tr>
    <tr class="section">
        <th colspan="3">Input</th>
    </tr>
    <tr class="raw">
        <th>Raw</th>
        <td>
            <pre>Sep 19 08:26:10 host CEF:0|security|threatmanager|1.0|100|Detected a =\\\||10|src=10.0.0.1 shost=10.0.0.1 msg=Detected a \=\\|.\n No action needed dmac=00-0D-60-AF-1B-61 cs2=WIFI cs2Label=SSID art=1 threatAttackID=T1132</pre>
        </td>
        <td></td>
    </tr>
    <tr class="section">
        <th colspan="3">CEF Header</th>
    </tr>
    <tr class="cefheader">
        <th>Version</th>
        <td>
            <pre>0</pre>
        </td>
        <td></td>
    </tr>
    <tr class="cefheader">
        <th>DeviceVendor</th>
        <td>
            <pre>security</pre>
        </td>
        <td></td>
    </tr>
    <tr class="cefheader">
        <th>DeviceProduct</th>
        <td>
            <pre>threatmanager</pre>
        </td>
        <td></td>
    </tr>
    <tr class="cefheader">
        <th>DeviceVersion</th>
        <td>
            <pre>1.0</pre>
        </td>
        <td></td>
    </tr>
    <tr class="cefheader">
        <th>SignatureID</th>
        <td>
            <pre>100</pre>
        </td>
        <td></td>
    </tr>
    <tr class="cefheader">
        <th>Name</th>
        <td>
            <pre>Detected a =\|</pre>
        </td>
        <td></td>
    </tr>
    <tr class="cefheader">
        <th>Severity</th>
        <td>
            <pre>10</pre>
        </td>
        <td></td>
    </tr>
    <tr class="section">
        <th colspan="3">CEF Extensions</th>
    </tr>
    <tr class="cefextension">
        <th title="agentReceiptTime">art</th>
        <td>
            <pre>1</pre>
        </td>
        <td>
            <ul>
                <li>agentReceiptTime</li>
                <li>Time Stamp</li>
                <li>The time at which information about the event was received by the ArcSight
                    connector.</li>
                <li class="status_notice">Consumer extension from CEF specification 0.1</li>
                <li class="status_notice"> 1970-01-01T00:00:00.001Z</li>
            </ul>
        </td>
    </tr>
    <tr class="cefextension">
        <th title="deviceCustomString2">cs2</th>
        <td>
            <pre>WIFI</pre>
        </td>
        <td>
            <ul>
                <li>deviceCustomString2</li>
                <li>Producer extension from CEF specification 0.1</li>
                <li>String[4000]</li>
                <li>One
                    of the six strings available to map fields that do not apply to any
                    other in this dictionary. Use sparingly and seek a more specific,
                    dictionary supplied field when possible.</li>
            </ul>
        </td>
    </tr>
    <tr class="cefextension">
        <th title="deviceCustomString2Label">cs2Label</th>
        <td>
            <pre>SSID</pre>
        </td>
        <td>
            <ul>
                <li>deviceCustomString2Label</li>
                <li>Producer extension from CEF specification 0.1</li>
                <li>String[1023]</li>
                <li>All
                    custom fields have a corresponding label field. Each of these fields is
                    a string and describes the purpose of the custom field.</li>
            </ul>
        </td>
    </tr>
    <tr class="cefextension">
        <th title="deviceMacAddress">dmac</th>
        <td class="status_warning">
            <pre>00-0D-60-AF-1B-61</pre>
        </td>
        <td>
            <ul>
                <li>deviceMacAddress</li>
                <li>Producer extension from CEF specification 0.1</li>
                <li>MAC Address</li>
                <li>Six colon-separated hexadecimal numbers. Example: “00:0D:60:AF:1B:61”</li>
                <li class="status_warning">Invalid format</li>
            </ul>
        </td>
    </tr>
    <tr class="cefextension">
        <th title="message">msg</th>
        <td>
            <pre>Detected a =\|.
 No action needed</pre>
        </td>
        <td>
            <ul>
                <li>message</li>
                <li>Producer extension from CEF specification 0.1</li>
                <li>String[1023]</li>
                <li>An
                    arbitrary message giving more details about the event. Multi-line
                    entries can be produced by using \n as the new line separator.</li>
            </ul>
        </td>
    </tr>
    <tr class="cefextension">
        <th title="sourceHostName">shost</th>
        <td>
            <pre>10.0.0.1</pre>
        </td>
        <td>
            <ul>
                <li>sourceHostName</li>
                <li>Producer extension from CEF specification 0.1</li>
                <li>String[1023]</li>
                <li>Identifies
                    the source that an event refers to in an IP network. The format should
                    be a fully qualified domain name (DQDN) associated with the source node,
                    when a mode is available. Examples:  “host” or “host.domain.com”.</li>
            </ul>
        </td>
    </tr>
    <tr class="cefextension">
        <th title="sourceAddress">src</th>
        <td>
            <pre>10.0.0.1</pre>
        </td>
        <td>
            <ul>
                <li>sourceAddress</li>
                <li>Producer extension from CEF specification 0.1</li>
                <li>IPv4 Address</li>
                <li>Identifies the source that an event refers to in an IP network. The format is
                    an IPv4 address. Example: “192.168.10.1”.</li>
            </ul>
        </td>
    </tr>
    <tr class="cefextension">
        <th title="Threat Attack ID">threatAttackID</th>
        <td>
            <pre>T1132</pre>
        </td>
        <td>
            <ul>
                <li>Threat Attack ID</li>
                <li>String[32]</li>
                <li>A full ID of a threat or attack as defined in the security framework in
                    frameworkName.</li>
                <li class="status_notice">Consumer extension from CEF specification 1.2</li>
            </ul>
        </td>
    </tr>
    <tr class="section">
        <th colspan="3">CEF Extensions by Label</th>
    </tr>
    <tr class="cefextension">
        <th>SSID</th>
        <td>
            <pre>WIFI</pre>
        </td>
        <td></td>
    </tr>
</table>

## Project setup

```sh
npm install
```

### Scrape CEF meta-data

Scrape CEF implementation standard and save producer and consumer extension dictionaries as JSON and CSV.

```sh
node ./docs/scrape.js > ./docs/fixes.txt
```

#### Compare CEF Implementation Standard and Flexconn Devguide

Generate a html side by side comparison of the CSV files for both documents using [diff2html-cli](https://www.npmjs.com/package/diff2html-cli).

On the `spec-vs-devguide` branch:

1) Scrape metadata
2) Commit `/docs/*.csv`
3) Copy `docs/extensions-dictionary-flexconn_devguide-for-comparison.csv` to `docs/extensions-dictionary-for-comparison.csv`
4) Create diff

```sh
node ./docs/scrape.js > ./docs/fixes.txt
git commit -m "Update scraped metadata" docs/*.html docs/*.csv docs/fixes.txt src/components/extension-dictionary.json
cp ./docs/extension-dictionary-flexconn_devguide-for-comparison.csv ./docs/extension-dictionary-for-comparison.csv
diff2html --style side --title "CEF Implementation Standard vs. Flexconn Devguide" --matchWordsThreshold 0.1 --fileContentToggle false --file docs/cef-implementation-standard_vs_flexconn-devguide.html
```

### Compiles and hot-reloads for development

```sh
npm run dev
```

### Compiles and minifies for production

```sh
npm run build
```

### Deploy to production

```sh
# initial
git subtree push --prefix dist origin gh-pages
# on updates
npm run deploy
```
