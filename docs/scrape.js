// Scrape CEF implementation standard and save producer and consumer extension dictionaries as JSON and CSV

const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const ObjectsToCsv = require('objects-to-csv');

const cefImplementationStandardUrl = 'https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/cef-implementation-standard/Content/CEF/Chapter%202%20ArcSight%20Extension.htm#'
const cefFlexconnDevguideUrl = 'https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/flexconn_devguide/Content/convertFlex/Appendix_ArcSight_Built-in_Mapping_Tokens.htm'
const producerDictionaryName = 'producer'
const consumerDictionaryName = 'consumer'
const devguideDictionaryName = 'devguide'

function parseExtension(dict, dictionaryName, $, element) {
    const tds = $(element).find('td');

    let version;
    let key;
    let fullName;
    let dataType;
    let length;
    let description;

    // extract the text from each cell
    if (dictionaryName == devguideDictionaryName) {
        fullName = $(tds[0]).text().trim();
        dataType = $(tds[1]).text().trim();
        length = $(tds[2]).text().trim();
        description = $(tds[3]).text().trim();
    } else {
        version = $(tds[0]).text().trim();

        const origKey = $(tds[1]).text().trim();
        key = origKey.replace(/[^0-9a-zA-Z]/g, '');
        if (key != origKey) {
            console.log('Fix key "' + origKey + '" -> "' + key + '"');
        }
        if (/^[A-Z]/.test(key)) {
            key = key.charAt(0).toLowerCase() + key.slice(1);
            console.log('Lower case first character of key "' + origKey + '" -> ' + key + '"');
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
    
    // fix data
    
    // ignore 1.2 *Key producer extensions that are actually consumer
    if (dictionaryName == producerDictionaryName && version == '1.2' && /Key$/.test(key)) {
        console.log('Ignore invalid extension for ' + dictionaryName + ': "' + key + '"')
        return;
    }
    // ignore 1.2 *Key consumer extensions that are actually producer
    if (dictionaryName == consumerDictionaryName && version == '1.2' && !/Key$/.test(key)) {
        console.log('Ignore invalid extension for ' + dictionaryName + ': "' + key + '"')
        return;
    }

    // fix fullNames beginning with idFile
    const origFullName = fullName;
    if (/^idFile/.test(fullName)) {
        fullName = origFullName.replace('id', 'old');
        if (fullName != origFullName) {
            console.log('Fix full name for key "' + key + '": ' + origFullName + '" -> "' + fullName + '"');
        }
    }

    // remove spaces from fullName
    const origFullName2 = fullName;
    fullName = fullName.replace(/[^0-9a-zA-Z]/g, '');
    if (fullName != origFullName2) {
        console.log('Fix full name for key "' + key + '": ' + origFullName + '" -> "' + fullName + '"');
    }

    // Lower case first character of fullName
    if (/^[A-Z]/.test(fullName)) {
        fullName = fullName.charAt(0).toLowerCase() + fullName.slice(1);
        console.log('Lower case first fullName character of "' + origFullName + '" -> ' + fullName);
    }

    // IP address extensions can take IPv6 now
    if (dataType == 'IPv4 Address') {
        console.log('Fix data type for key "' + key + '": ' + dataType + '-> IP Address');
        dataType = 'IP Address';
    }    

    if (length.startsWith('64-bit') || key == 'in' || key == 'out' || key == 'fsize' || key == 'oldFileSize') {
        console.log('Fix data type for key "' + key + '": ' + dataType + '-> Long');
        dataType = 'Long';
        length = '';
    }    

    // there is no more 4.x, set length to 4000
    if (length.startsWith('1023 (4.x)')) {
        console.log('Set length for key "' + fullName + '": ' + length + '-> 4000');
        length = '4000';
    }    

    // convert numeric length to Number
    if (dataType === 'String') {
        length = Number(length);
        if (Number.isNaN(length)) {
            length = undefined
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
        'description': description
    };

    // check for duplicate extensions
    for (let index = 0; index < dict.length; index++) {
        const element = dict[index];
        if ((key && key == element.key) || fullName == element.fullName) {
            console.log('Duplicate entry with key "' + key + '" and fullName "' + fullName + '"')
            return;
        }
    }

    dict.push(extension);
}

// input: array of property names, names starting with "-" are sorted reversely
const sortByFields = (fields) => (a, b) => fields.map(key => {
    let direction = 1;
    if (key[0] === '-') { direction = -1; key = key.substring(1); }
    return a[key] > b[key] ? direction : a[key] < b[key] ? -(direction) : 0;
}).reduce((p, n) => p ? p : n, 0);

function saveJson(arr, fileName) {
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
        console.log(fileName + ' file has been saved.');
    });
}

async function scrapeUrl(url) {
    const response = await axios(url)
    const html = await response.data;
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

        // sort dictionary by dictionaryName (producer first), version, key, and fullName
        dictionary.sort(sortByFields(['-dictionaryName', 'version', 'key', 'fullName']));

        let csv = new ObjectsToCsv(dictionary);
        await csv.toDisk('docs/extension-dictionary.csv')

        saveJson(dictionary, 'src/components/extension-dictionary.json');
    } else {
        let dictionary = [];
        const devguideRows = $('tbody tr');
        //Looping through the rows
        devguideRows.each((index, element) => {
            parseExtension(dictionary, devguideDictionaryName, $, element);
        })

        let csv = new ObjectsToCsv(dictionary);
        await csv.toDisk('docs/extension-dictionary-flexconn_devguide.csv')
    }
}

scrapeUrl(cefImplementationStandardUrl);
scrapeUrl(cefFlexconnDevguideUrl);
