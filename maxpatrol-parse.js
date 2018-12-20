/* eslint-disable default-case, no-continue */

'use strict';

const XmlStream = require('xml-stream');
const ipUtils = require('ip');
const moment = require('moment');

const {
  parseReferenceLinks,
  getWindowsSoftwareData,
  getLinuxSoftwareData,
  getWindowsUserData,
  getNetworkDeviceNetworkAdapterData,
  getNetworkInterfaceData,
  getNetworkDeviceFirmwareData,
  getNetworkDeviceOrLinuxUserData,
  getSNMPNetworkAddresses,
  getSNMPNetworkInterfaces,
  getSNMPSystemInformation,
  formatSNMPInterfaces,
  getSerialNumbers,
} = require('./maxpatrol-helper');


/**
 * Парсим данные о софте хоста
 * @param {Array} data
 * @returns {{
 * software: Array,
 * ifs: Array,
 * vulns: Object,
 * ports: Array,
 * firmware: Object,
 * users: Array
 * }}
 */
function parseHostSoft(data) {
  const ifs = [];
  const users = [];
  const ports = [];
  const vulns = {};
  let software = [];
  let firmware;
  const os = (data.length === 1) ? `${data[0].name} ${data[0].version}` : undefined;

  for (const item of data) {
    const {
      vulners,
      port,
      protocol,
    } = item;

    if (port > 0) {
      ports.push(port);
    }

    if (vulners && vulners.vulner) {
      for (const vuln of vulners.vulner) {
        const { id: vulnerId } = vuln.$;
        let user;
        let soft;
        let networkInterface = {
          address: [],
        };

        switch (vulnerId) {
          case '4424673': // сетевой интерфейс Windows и Linux
            networkInterface = getNetworkInterfaceData(vuln);
            break;
          case '425336': // сетевой интерфейс сетевого оборудования
            networkInterface = getNetworkDeviceNetworkAdapterData(vuln);
            break;
          case '401005': // пользователи Windows
            user = getWindowsUserData(vuln);
            break;
          case '425318':
          case '411402': // пользователи Linux или сетевого оборудования
            user = getNetworkDeviceOrLinuxUserData(vuln);
            break;
          case '401000': // софт Windows
            soft = getWindowsSoftwareData(vuln);
            break;
          case '175492': // софт Linux
            soft = getLinuxSoftwareData(vuln);
            break;
          case '411401': // прошивка сетевого оборудования
            firmware = getNetworkDeviceFirmwareData(vuln);
            break;
          default: // собственно уязвимость (внезапно)
            vulns[vulnerId] = {
              port,
              protocol,
            };
        }

        if (networkInterface && networkInterface.address && networkInterface.address.length) {
          ifs.push(networkInterface);
        }

        if (soft) {
          software = Array.isArray(soft) ? [...software, ...soft] : [...software, soft];
        }

        if (user) {
          users.push(user);
        }
      }
    }
  }

  return {
    ifs,
    software,
    users,
    ports,
    vulns,
    firmware,
    os,
  };
}

/**
 * Парсим данные сканирования по SNMP
 * @param {Array} data
 * @returns {{ifs: Array, name: string}}
 */
function parseSNMPData(data) {
  let addresses = [];
  let interfaces = [];
  let name = '';

  for (const vuln of data.vulners.vulner) {
    switch (vuln.$.id) {
      case '8167':
        interfaces = getSNMPNetworkInterfaces(vuln);
        break;
      case '8168':
        ({ name } = getSNMPSystemInformation(vuln));
        break;
      case '8169':
        addresses = getSNMPNetworkAddresses(vuln);
        break;
    }
  }

  return {
    ifs: formatSNMPInterfaces(addresses, interfaces),
    name,
  };
}

/**
 * Парсим данные о hardware хоста
 * @param {Array} data
 * @returns {{ serial: String }}
 */
function parseHardwareData(data) {
  let serial = {};

  for (const item of data) {
    if (item.$.id === '425302') {
      serial = getSerialNumbers(item);
    }
  }

  return {
    serial,
  };
}

/**
 * Форматируем данные о софте хоста
 * @param {Array} softData
 * @returns {{formattedSoft: Array, ports: Array}}
 */
function formatSoftData(softData) {
  const ports = [];
  const formattedSoft = [];

  for (const item of softData) {
    const port = item.$.port && Number(item.$.port);
    let protocol = item.$.protocol && Number(item.$.protocol);

    switch (protocol) {
      case 6:
        protocol = 'tcp';
        break;
      case 17:
        protocol = 'udp';
        break;
    }

    formattedSoft.push({
      ...item,
      port,
      protocol,
    });

    // Список открытых портов
    if (port > 0) {
      ports.push(port);
    }
  }

  return {
    formattedSoft,
    ports,
  };
}

/**
 * Форматируем данные о софте и получаем из них необходимые данные
 * @param {Array} data
 * @returns {{
 *  software: Array,
 *  os: String,
 *  ifs: Array,
 *  vulns: Object,
 *  ports: Array,
 *  firmware: Object,
 *  users: Array
 * }}
 */
function parseSoftData(data) {
  const { formattedSoft, ports } = formatSoftData(data);
  const snmpData = formattedSoft.find(item => item.name === 'SNMP');
  const osData = formattedSoft.find(item => item.name === 'Operating System');
  const os = osData ? osData.version : '';

  let result = parseHostSoft(formattedSoft);

  // если данных нет, но есть данные SNMP-сканирования - используем последние
  if ((!result.ifs || result.ifs.length === 0) &&
    (snmpData && snmpData.vulners && snmpData.vulners.vulner && snmpData.vulners.vulner.length)) {
    result = parseSNMPData(snmpData);
  }

  return {
    ...result,
    ports,
    os: result.os || os,
  };
}

/**
 * Фильтруем сетевые интерфейсы - отбрасываем локальные адреса и все адреса, непохожие на IPV4
 * @param {Array} interfaces
 * @returns {Array}
 */
function filterNetworkInterfaces(interfaces) {
  const formattedInterfaces = [];

  for (const ifs of interfaces) {
    ifs.address = ifs.address.filter(item => !['127.0.0.1', 'localhost'].includes(item.ip) &&
      ipUtils.isV4Format(item.ip));

    if (ifs.address.length) {
      formattedInterfaces.push(ifs);
    }
  }

  return formattedInterfaces;
}

/**
 * Парсит xml отчет из MaxPatrol
 * @param {Stream} inputStream - readable поток с отчетом
 * @param {Object} options
 * @param {Function} cb - колбэк, который должен быть вызван по завершении парсинга
 */
module.exports = function (inputStream, options = {}, cb) {
  const errors = [];
  const { last_run: lastRun } = options;

  const xml = new XmlStream(inputStream);

  xml.collect('scan_objects > soft');
  xml.collect('scan_objects > soft > vulners > vulner');
  xml.collect('scan_objects > soft > vulners > vulner > param_list');
  xml.collect('scan_objects > soft > vulners > vulner > param_list > table');
  xml.collect('scan_objects > soft > vulners > vulner > param_list > table > body');
  xml.collect('scan_objects > soft > vulners > vulner > param_list > table > body > row');
  xml.collect('scan_objects > soft > vulners > vulner > param_list > table > body > row > field');

  // в результатах всего один ряд значений, так что остальное нас не интересует
  xml.collect('hardware > device');
  xml.collect('hardware > device > param_list');
  xml.collect('hardware > device > param_list > table');
  xml.collect('hardware > device > param_list > table > body');
  xml.collect('hardware > device > param_list > table > body > row');
  xml.collect('hardware > device > param_list > table > body > row > field');

  xml.collect('content > vulners > vulner');
  xml.collect('content > vulners > vulner > global_id');

  // undocumented feature, second parameter preserves whitespaces
  xml.preserve('content > vulners > vulner > description', true);

  const uniqueVulns = {};
  let hosts = [];

  xml.on('endElement: host', (node) => {
    // парсим данные хоста - тут все самое интересное
    const {
      fqdn,
      netbios,
      stop_time: stopTime,
      host_uid: maxpatrolUid,
    } = node.$;

    const stop = Number(new Date(stopTime));
    if (stop && lastRun && stop < lastRun) {
      return true;
    }

    try {
      const softData = typeof node.scan_objects === 'object' && node.scan_objects.soft ?
        parseSoftData(node.scan_objects.soft) :
        {};

      const ifs = filterNetworkInterfaces(softData.ifs || []);
      if (!ifs || ifs.length === 0) {
        return true;
      }

      const hardware = node.hardware && node.hardware.device ?
        parseHardwareData(node.hardware.device) :
        {};

      const scanFinished = moment(stopTime).format();

      hosts.push({
        ...softData,
        ...hardware,
        maxpatrolUid,
        ifs,
        software: options.import_software ? softData.software : [],
        users: options.import_users ? softData.users : [],
        name: fqdn || netbios || softData.name || ifs[0].address[0].ip,
        updated_at: scanFinished,
        vuln_discovery_date: scanFinished,
        vuln_elimination_date: scanFinished,
      });
    } catch (e) {
      errors.push(new Error(`Error: id ${maxpatrolUid} - ${e.message}`));
    }
  });

  xml.on('endElement: content > vulners > vulner', (el) => {
    // парсим уязвимости
    const {
      description,
      cvss,
      title,
      links,
      $,
      short_description: shortDescription,
      how_to_fix: remediation,
      global_id: globalId,
    } = el;

    // не учитываем уязвимости, у которых нет global_id и cvss.base_score
    if ((!globalId || globalId.length === 0) && (!cvss || !cvss.$.base_score || cvss.$.base_score === '0.0')) {
      return;
    }

    try {
      const level = Math.round(Number(cvss.$.base_score) / 2);
      const vulnDescription = description.$text || shortDescription.$text || '';
      const vuln = {
        description: vulnDescription.replace(/  +/g, ' '),
        name: title,
        remediation,
        uid: $.id,
        reference: parseReferenceLinks(links),
        level_id: level === 0 ? 1 : level,
      };

      if (vuln.uid) {
        uniqueVulns[vuln.uid] = vuln;
      }
    } catch (e) {
      errors.push(new Error(`Error: vulner id ${globalId} - ${e.message}`));
    }
  });

  xml.on('error', (err) => {
    errors.push(err);
  });

  xml.on('end', () => {
    // маппим уязвимости с хостами и возвращаем результат
    hosts = hosts.map((host) => {
      const vulnerabilities = [];
      if (host.vulns) {
        for (const key in host.vulns) {
          const vuln = host.vulns[key];
          const uniqueVuln = uniqueVulns[key];

          if (uniqueVuln) {
            let vulnerability = uniqueVuln;

            if (vuln.port) {
              vulnerability = {
                ...vulnerability,
                ...vuln,
                isNetworkVulnerability: !!vuln.port,
              };
            }

            vulnerabilities.push(vulnerability);
          }
        }
      }

      delete host.vulns;
      delete host.maxpatrolUid;

      return {
        ...host,
        vulnerabilities,
      };
    });

    cb(null, { hosts, errors });
  });
};
