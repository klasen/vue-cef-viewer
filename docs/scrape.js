// Scrape CEF implementation standard and save producer and consumer extension dictionaries as JSON and CSV

const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const ObjectsToCsv = require("objects-to-csv");

const cefImplementationStandardUrl = 'https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/cef-implementation-standard/Content/CEF/Chapter%202%20ArcSight%20Extension.htm#'

let dictionary = [];

function parseExtension(dict, dictionaryName, $, element) {
    const tds = $(element).find('td');

    //Extracting the text out of each cell
    const version = $(tds[0]).text().trim();
    const rawkey = $(tds[1]).text().trim();
    let fullName = $(tds[2]).text().trim();
    let dataType = $(tds[3]).text().trim();
    let length = $(tds[4]).text().trim();
    // use first <p> element to skip note div
    let description;
    const desc = $(tds[5]).find('p');
    if (desc.length > 0) {
        description = $(tds[5]).find('p').text().trim();
    } else {
        description = $(tds[5]).text().trim();
    }

    // fix data
    const key = rawkey.replace(/[^0-9a-zA-Z]/g, '');
    if (key != rawkey) {
        console.log('Invalid key "' + rawkey + '" -> ' + key);
    }

    if (dataType=="IPv4 Address") {
        console.log('Fix data type for key "' + rawkey + '": ' + dataType + "-> IP Address");
        dataType = "IP Address";
    }

    if (length.startsWith('64-bit') || rawkey == 'in' || rawkey == 'out') {
        console.log('Fix data type for key "' + rawkey + '": ' + dataType + "-> Long");
        dataType = 'Long';
        length = '';
    }

    let extension = {
        'dictionaryName': dictionaryName,
        'version': version,
        'key': key,
        'fullName': fullName,
        'dataType': dataType,
        'length': dataType === "String" ? Number(length) : length,
        'description': description,
    };

    dict.push(extension);
}

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

(async function scrapeCefImplementationStandardUrl() {
    const response = await axios(cefImplementationStandardUrl)
    const html = await response.data;
    const $ = cheerio.load(html);

    //Selecting all rows inside our target table

    const producerRows = $('.table_2:nth-of-type(1) tbody tr');
    //Looping through the rows
    producerRows.each((index, element) => {
        parseExtension(dictionary, 'producer', $, element);
    })

    const consumerRows = $('.table_2:nth-of-type(2) tbody tr');
    //Looping through the rows
    consumerRows.each((index, element) => {
        parseExtension(dictionary, 'consumer', $, element);
    })

    // console.dir(producerDictionary);
    // console.dir(consumerDictionary);

    let csv = new ObjectsToCsv(dictionary);
    await csv.toDisk('docs/extension-dictionary.csv')

    saveJson(dictionary, 'src/components/extension-dictionary.json');
})();
