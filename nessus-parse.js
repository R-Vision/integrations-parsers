/* eslint-disable no-cond-assign */
/* eslint-disable no-restricted-syntax */

const csvParse = require('csv-parse');

/**
 * Получает уровень уязвимости по CVSS
 * @param {number} number - CVSS
 * @returns {number} - Уровень уязвимости
 */
function getLevel(number) {
  if (number >= 9) {
    return 5;
  }

  if (number >= 7) {
    return 4;
  }

  if (number >= 5) {
    return 3;
  }

  if (number >= 3) {
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
  // eslint-disable-next-line no-useless-escape
  return url.match(/^\w+:\/\/([^\/]+)/)[1];
}

/**
 * Парсит CSV отчет из Nessus
 * @param {Stream} stream - readable поток с отчетом
 * @param {Function} cb - callback. вызывается после завершения работы функции
 */
module.exports = function nessusParse(stream, cb) {
  const hosts = {};

  const parser = csvParse({
    from_line: 2,
  });

  stream.pipe(parser);

  parser.on('error', err => cb(err));

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

    // errors пока не используются, но нужно чтобы совпадал формат с результатом парсинга MP
    cb(null, { hosts: result, errors: [] });
  });

  function processRecord(record) {
    const {
      0: pluginId,
      1: cve,
      2: cvss,
      4: address,
      5: protocol,
      6: port,
      7: name,
      9: description,
      10: remediation,
      11: seeAlso,
      12: result,
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

    if (!hosts[address].vulnerabilities[`${pluginId}-${port}-${protocol}`]) {
      let reference = [];

      if (seeAlso) {
        const urls = seeAlso.split('\n');

        reference = urls
          .map(url => url.trim())
          .map(url => ({
            ref_id: url,
            source: getSourceFromUrl(url),
            ref_url: url,
          }));
      }

      if (cve) {
        reference.push({
          ref_id: cve,
          source: 'NVD',
          ref_url: `http://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`,
        });
      }

      // default level is 1
      let level = 1;

      if (cvss) {
        level = getLevel(parseInt(cvss, 10));
      }

      const item = {
        name,
        description,
        level_id: level,
        uid: pluginId,
        remediation,
        result,
      };

      if (port > 0) {
        item.port = port;
        item.protocol = protocol;
        item.isNetworkVulnerability = true;
      }

      if (reference) {
        item.reference = reference;
      }

      hosts[address].vulnerabilities[`${pluginId}-${port}-${protocol}`] = item;
    } else if (cve) {
      hosts[address].vulnerabilities[
        `${pluginId}-${port}-${protocol}`
      ].reference.push({
        ref_id: cve,
        source: 'NVD',
        ref_url: `http://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`,
      });
    }
  }

  parser.on('readable', () => {
    let record;

    while ((record = parser.read())) {
      processRecord(record);
    }
  });
};
