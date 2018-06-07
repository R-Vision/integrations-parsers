'use strict';

const csvParse = require('csv-parse');

/**
 * Получает уровень уязвимости по CVSS
 * @param {number} number - CVSS
 * @returns {number} - Уровень уязвимости
 */
function getLevel(number) {
    if (number >= 9) {
        return 5;
    } else if (number >= 7) {
        return 4;
    } else if (number >= 5) {
        return 3;
    } else if (number >= 3) {
        return 2;
    }
    return 1;
}

/**
 * Парсит имя источника из URL
 * @param {String} url - URL
 * @returns {String} Источник
 */
function getSourceFromUrl(url) {
    return url.match(/^\w+:\/\/([^\/]+)/)[1];
}

/**
 * Парсит CSV отчет из Nessus
 * @param {Stream} stream - readable поток с отчетом
 * @param {Function} cb - callback. вызывается после завершения работы функции
 */
module.exports = function nessusParse(stream, cb) {
    const hosts = {};

    const parser = csvParse({ columns: () => {} });

    stream.pipe(parser);

    parser.on('readable', () => {
        let record;

        while (record = parser.read()) {
            processRecord(record);
        }
    });

    parser.on('end', () => {
        const result = [];

        for (const item of Object.values(hosts)) {
            const vulns = [];

            for (const vuln of Object.values(item.vulnerabilities)) {
                vulns.push(vuln);
            }
            item.vulnerabilities = vulns;
            result.push(item);
        }

        cb(null, result);
    });

    function processRecord(record) {
        const {
            0: pluginId,
            1: cve,
            2: cvss,
            4: address,
            7: name,
            9: description,
            10: remediation,
            11: seeAlso,
        } = record;

        if (!address || !pluginId) {
            return;
        }

        if (!hosts[address]) {
            hosts[address] = {
                ip: address,
                hostname: address,
                vulnerabilities: {},
            };
        }

        if (!hosts[address].vulnerabilities[pluginId]) {
            let reference = [];

            if (seeAlso) {
                const urls = seeAlso.split('\n');

                reference = urls.map(url => {
                    url = url.trim();

                    return {
                        ref_id: url,
                        source: getSourceFromUrl(url),
                        ref_url: url,
                    };
                });
            }

            if (cve) {
                reference.push({
                    ref_id: cve,
                    source: 'NVD',
                    ref_url: `http://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`,
                });
            }

            let level = 0;

            if (cvss) {
                level = getLevel(parseInt(cvss, 10));
            }

            const item = {
                name,
                description,
                level_id: level,
                uid: pluginId,
                remediation,
            };

            if (reference) {
                item.reference = reference;
            }

            hosts[address].vulnerabilities[pluginId] = item;
        } else if (cve) {
            hosts[address].vulnerabilities[pluginId].reference.push({
                ref_id: cve,
                source: 'NVD',
                ref_url: `http://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`,
            });
        }
    }
};
