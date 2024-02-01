// Scrape CEF implementation standard and save producer and consumer extension dictionaries as JSON and CSV

const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const ObjectsToCsv = require('objects-to-csv');

const cefImplementationStandardUrl = 'https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.1/cef-implementation-standard/Content/CEF/arcsight-extensions.htm'
const cefFlexconnDevguideUrl = 'https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.1/flexconn_devguide/Content/convertFlex/Appendix_ArcSight_Built-in_Mapping_Tokens.htm'
const producerDictionaryName = 'producer'
const consumerDictionaryName = 'consumer'
const devguideDictionaryName = 'devguide'

let firstDmac = true; // dmac key occurs twice
let hasDvcMac = false; // dvcmac disappeared

function parseExtension(dict, dictionaryName, $, element) {
    const tds = $(element).find('td');

    let version;
    let key;
    let fullName;
    let dataType;
    let length;
    let description;

    let origKey;

    // extract the text from each cell
    if (dictionaryName == devguideDictionaryName) {
        version = '0.1';
        fullName = $(tds[0]).text().trim();
        dataType = $(tds[1]).text().trim();
        length = $(tds[2]).text().trim();
        description = $(tds[3]).text().trim();
    } else {
        version = $(tds[0]).text().trim();

        origKey = $(tds[1]).text().trim();
        key = origKey.replace(/[^0-9a-zA-Z]/g, '');
        if (key != origKey) {
            console.log('Remove spaces from key "' + origKey + '" -> "' + key + '"');
        }
        if (/^[A-Z]/.test(key)) {
            key = key.charAt(0).toLowerCase() + key.slice(1);
            console.log('Lower case first character of key "' + origKey + '" -> "' + key + '"');
        }

        fullName = $(tds[2]).text().trim();

        dataType = $(tds[3]).text().trim();

        length = $(tds[4]).text().trim();

        // use first <p> element to skip note div
        const desc = $(tds[5]).find('p');
        if (desc.length > 0) {
            description = desc.text().trim();
        } else {
            description = $(tds[5]).text().trim();
        }
    }

    const origDataType = dataType;
    const origFullName = fullName;

    // fix data

    // remove producer extensions that are actually consumer
    if (dictionaryName == producerDictionaryName && ((version == '1.2' && /^parser|Key$/.test(key))) || key == 'type') {
        console.log('Remove consumer extension from ' + dictionaryName + ' dictionary: "' + key + '"')
        return;
    }
    // remove consumer extensions that are actually producer
    if (dictionaryName == consumerDictionaryName && version == '1.2' && /^reported|^framework|^threat/.test(key)) {
        console.log('Remove producer extension from ' + dictionaryName + ' dictionary: "' + key + '"')
        return;
    }

    // fix data for specific keys
    switch (key) {
        case 'dmac':
            if (firstDmac) {
                firstDmac = false;
                if (fullName != 'destinationMacAddress') {
                    fullName = 'destinationMacAddress';
                    console.log('Fix full name for key "' + key + '": "' + origFullName + '" -> "' + fullName + '"');
                }
            }
            break;
        case 'destinatioTranslatedZoneExternalID':
            key = 'destinationTranslatedZoneExternalID';
            console.log('Fix key for key "' + origKey + '" -> "' + key + '"');
            break;
        case 'dvcmac':
            hasDvcMac = true;
            break;
        case 'flexString1Label':
            if (fullName != 'flexString1Label') {
                fullName = 'flexString1Label';
                console.log('Fix full name for key "' + key + '": "' + origFullName + '" -> "' + fullName + '"');
            }
            break;
        case 'fname':
            fullName = 'fileName';
            console.log('Fix full name for key "' + key + '": "' + origFullName + '" -> "' + fullName + '"');
            break;
        case 'reportedDuration':
            if (dataType != 'Long') {
                dataType = 'Long';
                console.log('Fix data type for key "' + key + '": "' + origDataType + '" -> "' + dataType + '"');
            }
            break;
        case 'threatActor':
            fullName = 'threatActor';
            console.log('Fix full name for key "' + key + '": "' + origFullName + '" -> "' + fullName + '"');
            break;
        default:
            break;
    }

    // fix data for specific full names
    switch (fullName) {
        case 'deviceMacAddress': {
            if (dictionaryName != devguideDictionaryName) {
                const origKey = key;
                key = 'dvcmac';
                console.log('Fix key "' + (origKey ? origKey : fullName) + '" -> "' + key + '"');
            }
            break;
        }
        case 'deviceCustomIPv6Address1':
        case 'deviceCustomIPv6Address2':
        case 'deviceCustomIPv6Address3':
            dataType = 'IPv6 Address';
            break;
        case 'agentSeverity':
        case 'deviceEventClassId':
        case 'deviceProduct':
        case 'deviceSeverity':
        case 'deviceVersion':
        case 'deviceVendor':
        case 'name':
            console.log('Ignore CEF header field "' + fullName + '"');
            return;
        default:
            break;
    }

    // normalize dataType
    switch (dataType) {
        case 'Floating Point':
            dataType = 'Double';
            console.log('Normalize data type for key "' + (key ? key : fullName) + '": "' + origDataType + '" -> "' + dataType + '"');
            break;
        case 'IPv4 Address': // IP address extensions can take IPv6 now
        case 'IPAddress':
        case 'IP Address':
            dataType = 'IpAddress';
            console.log('Normalize data type for key "' + (key ? key : fullName) + '": "' + origDataType + '" -> "' + dataType + '"');
            break;
        case 'IPv6 address':
            dataType = 'IPv6 Address';
            console.log('Normalize data type for key "' + (key ? key : fullName) + '": "' + origDataType + '" -> "' + dataType + '"');
            break;
        case 'Mac Address':
        case 'MAC address':
        case 'MAC Address':
            dataType = 'MacAddress';
            console.log('Normalize data type for key "' + (key ? key : fullName) + '": "' + origDataType + '" -> "' + dataType + '"');
            break;
        case 'TimeStamp':
        case 'Time Stamp':
            dataType = 'DateTime';
            console.log('Normalize data type for key "' + (key ? key : fullName) + '": "' + origDataType + '" -> "' + dataType + '"');
            break;
        default:
            break;
    }

    if (dataType != 'Long' && (key == 'in' || key == 'out' || key == 'fsize' || key == 'oldFileSize')) {
        dataType = 'Long';
        length = '';
        console.log('Fix data type for key "' + (key ? key : fullName) + '": "' + origDataType + '" -> "' + dataType + '"');
    }

    if (length.startsWith('64-bit')) {
        dataType = 'Long';
        length = '';
        console.log('Fix data type for key "' + (key ? key : fullName) + '": "' + origDataType + '" -> "' + dataType + '"');
    }

    if (length.startsWith('n/a')) {
        console.log('Normalize length for key "' + (key ? key : fullName) + '": "' + length + '" -> ""');
        length = '';
    }

    if (description.endsWith('(2)')) {
        // Note (2): Although URI fields can be set using the FlexConnector properties file, these are really links to resources in the database. Therefore, it is recommended that those fields be set using the network-model and customer-setting features.
        length = '2048';
    }
    // there is no more 4.x, set length to 4000
    if (length.startsWith('1023 (4.x)')) {
        console.log('Adjust length for key "' + (key ? key : fullName) + '": ' + length + ' -> 4000');
        length = '4000';
    }

    // convert numeric length to Number
    if (dataType === 'String') {
        length = Number(length);
        if (Number.isNaN(length)) {
            console.log('Non-numeric string length for key: "' + (key ? key : fullName) + '": ' + length)
            length = undefined;
        }
    }

    // normalize fullName so we can map between Dev Guide an Implementation Standard
    // remove spaces from fullName
    var normalizedFullName = fullName.replace(/[^0-9a-zA-Z]/g, '');
    // Lower case first character of fullName
    if (/^[A-Z]/.test(normalizedFullName)) {
        normalizedFullName = normalizedFullName.charAt(0).toLowerCase() + normalizedFullName.slice(1);
    }
    // if (normalizedFullName != origFullName) {
    //     console.log('Normalize full name: "' + origFullName + '" -> "' + normalizedFullName + '"');
    // }

    // check for duplicate extensions
    for (let index = 0; index < dict.length; index++) {
        const element = dict[index];
        if ((key && key == element.key) || fullName == element.fullName) {
            console.log('Duplicate entry with key "' + key + '" and fullName "' + fullName + '"')
            return;
        }
    }

    // add to results
    let extension = {
        'dictionaryName': dictionaryName,
        'version': version,
        'key': key,
        'fullName': fullName,
        'dataType': dataType,
        'length': length,
        'description': description,
        'normalizedFullName': normalizedFullName
    };
    dict.push(extension);
}

// input: array of property names, names starting with "-" are sorted reversely
const sortByFields = (fields) => (a, b) => fields.map(key => {
    let direction = 1;
    if (key[0] === '-') { direction = -1; key = key.substring(1); }
    return a[key] > b[key] ? direction : a[key] < b[key] ? -(direction) : 0;
}).reduce((p, n) => p ? p : n, 0);

function saveJson(arr, fileName) { // eslint-disable-line no-unused-vars
    // transform array of objects into map
    let extensionMap = {};
    for (let extension of arr) {
        const key = extension.key;
        delete extension.key;
        extensionMap[key] = extension;
    }

    fs.writeFile(fileName, JSON.stringify(extensionMap, null, 0), 'utf8', function (err) {
        if (err) {
            console.log('An error occured while writing JSON Object to File.');
            return console.log(err);
        }
        // console.log(fileName + ' file has been saved.');
    });
}

async function scrapeUrl(url) {
    console.log('Scraping ' + url);
    const response = await axios(url)
    const html = response.data;
    fs.writeFile(url == cefImplementationStandardUrl ? 'docs/extension-dictionary.html' : 'docs/extension-dictionary-flexconn_devguide.html', html, 'utf8', function (err) {
        if (err) {
            console.log('An error occured while writing HTTP response to File.');
            return console.log(err);
        }

    });

    const $ = cheerio.load(html);

    if (url == cefImplementationStandardUrl) {
        let dictionary = [];

        //Selecting all rows inside our target table
        const producerRows = $('.table_2:nth-of-type(1) tbody tr');
        //Looping through the rows
        producerRows.each((index, element) => {
            parseExtension(dictionary, producerDictionaryName, $, element);
        })

        const consumerRows = $('.table_2:nth-of-type(2) tbody tr');
        consumerRows.each((index, element) => {
            parseExtension(dictionary, consumerDictionaryName, $, element);
        })

        if (!hasDvcMac) {
            let extension = {
                'dictionaryName': 'producer',
                'version': '0.1',
                'key': 'dvcmac',
                'fullName': 'deviceMacAddress',
                'dataType': 'MacAddress',
                'length': undefined,
                'description': 'Six colon-separated hexadecimal numbers. Example: “00:0D:60:AF:1B:61”',
                'normalizedFullName': 'deviceMacAddress'
            };
            dictionary.push(extension);
            console.log('Added missing extension for key "' + extension.key + '"');
        }

        // dictionary with fewer columns for comparison with flexconn_devguide
        let comparisonDictionary = [];
        dictionary.map((element) => {
            // if (element.dictionaryName == producerDictionaryName) {
            comparisonDictionary.push({
                'fullName': element.normalizedFullName,
                'dataType': element.dataType,
                'length': element.length,
            });
            // }
        });
        comparisonDictionary.sort(sortByFields(['fullName']));
        let csv = new ObjectsToCsv(comparisonDictionary);
        await csv.toDisk('docs/extension-dictionary-for-comparison.csv')

        // remove normalizedFullName that was neded for comparison
        dictionary.forEach(element => delete element.normalizedFullName);

        // sort dictionary by dictionaryName (producer first), version, key, and fullName
        dictionary.sort(sortByFields(['-dictionaryName', 'version', 'key', 'fullName']));

        csv = new ObjectsToCsv(dictionary);
        await csv.toDisk('docs/extension-dictionary.csv')

        saveJson(dictionary, 'src/components/extension-dictionary.json');
    } else {
        let dictionary = [];
        const devguideRows = $('tbody tr');
        //Looping through the rows
        devguideRows.each((index, element) => {
            parseExtension(dictionary, devguideDictionaryName, $, element);
        })

        // dictionary with fewer columns for comparison with cefImplementationStandard
        let comparisonDictionary = [];
        dictionary.map(element => comparisonDictionary.push({
            'fullName': element.normalizedFullName,
            'dataType': element.dataType,
            'length': element.length,
        }));
        comparisonDictionary.sort(sortByFields(['fullName']));
        let csv = new ObjectsToCsv(comparisonDictionary);
        await csv.toDisk('docs/extension-dictionary-flexconn_devguide-for-comparison.csv')

        // remove normalizedFullName that was neded for comparison
        dictionary.forEach(element => delete element.normalizedFullName);

        // sort dictionary by dictionaryName (producer first), version, key, and fullName
        dictionary.sort(sortByFields(['-dictionaryName', 'version', 'key', 'fullName']));

        csv = new ObjectsToCsv(dictionary);
        await csv.toDisk('docs/extension-dictionary-flexconn_devguide.csv')

    }
}

async function main() {
    await scrapeUrl(cefImplementationStandardUrl);
    console.log('');
    await scrapeUrl(cefFlexconnDevguideUrl);
}

main();
