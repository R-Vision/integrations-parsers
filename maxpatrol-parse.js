/* eslint-disable no-plusplus, default-case, no-continue */

'use strict';

const XmlStream = require('xml-stream');
const url = require('url');
const _ = require('lodash');
const ipUtils = require('ip');

const blockedSoftware = [
  'Microsoft Windows',
  'Microsoft Updates',
  'Microsoft Active Directory',
  'Microsoft DNS Server',
  'OpenSSH Server',
  'Network Configuration',
  'Samba',
  'Linux Kernel',
  'debian kernel',
  'Ubuntu Kernel',
  'Operating System',
  'OpenSSL',
  'Juniper JUNOS',
  'Oracle Database',
];

const ipAndMaskRegExp = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/;
const newIpAndMaskRegExp = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\(\/(\d{1,2})\)/;
const ciscoIpAndMaskRegExp = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})/;
const macAddressRegExp = /[a-fA-F0-9:]{17}|[a-fA-F0-9]{12}/;

function formatTwoDimentionalParamListTable(paramList, valueId) {
  const body = _.get(paramList, '[0].table[0].body[0].row');
  const item = {};

  if (body) {
    body.forEach((row, rowIndex) => {
      row.field.forEach((field, fieldIndex) => {
        if (fieldIndex === valueId) {
          item[rowIndex + 1] = field.$text;
        }
      });
    });
  }

  return _.isEmpty(item) ? undefined : item;
}

function formatSingleDimentionalParamListTable(paramList, returnFirstItem) {
  const result = [];
  const body = _.get(paramList, '[0].table[0].body[0].row');

  if (body) {
    body.forEach((row) => {
      const item = {};

      row.field.forEach((field) => {
        item[field.$.id] = field.$text;
      });

      if (item) {
        result.push(item);
      }
    });
  }

  if (returnFirstItem && result.length) {
    return result[0];
  }

  return result;
}

/**
 * По ссылке на уязвимость получает название БД с уязвимостями
 * @param {String[]} links - массив ссылок на  уязвимость
 * @returns {String[]}
 */
function parseReferenceLinks(links) {
  function defaultCb(match) {
    return match.toString().toUpperCase();
  }

  return links.replace(/[\n\t\r]/g, ' ')
    .split(' ')
    .reduce((reference, link) => {
      const uri = url.parse(link);

      const config = {
        cve: {
          regexp: /(CVE-\d+-\d+)/gim,
          source: 'CVE',
        },
        rhsa: {
          regexp: /(RHSA-\d+-\d+)/gim,
          source: 'RedHat',
        },
        ms: {
          regexp: /(ms\d+-\d+)/gim,
          source: 'Microsoft',
        },
        bid: {
          regexp: /(bid\/\d+)/gim,
          source: 'SecurityFocus',
        },
        xfdb: {
          regexp: /(xfdb\/\d+)/gim,
          source: 'X-Force',
        },
        dsa: {
          regexp: /(dsa-\d+)/gim,
          source: 'Debian',
        },
        usn: {
          regexp: /(usn-\d+-\d+)/gim,
          source: 'Ubuntu',
        },
        mdksa: {
          regexp: /(MDKSA-\d+:\d+)/gim,
          source: 'Mandriva',
        },
        asa: {
          regexp: /(ASA-\d+-\d+)/gim,
          source: 'Avaya',
        },
        glsa: {
          regexp: /(glsa-\d+-\d+)/gim,
          source: 'Gentoo',
        },
        esx: {
          regexp: /(esx-\d+)/gim,
          source: 'VMware',
        },
        rpl: {
          regexp: /(RPL-\d+)/gim,
          source: 'Rpath',
        },
        vmsa: {
          regexp: /(VMSA-\d+-\d+)/gim,
          source: 'VMware',
        },
        jsa: {
          regexp: /(JSA\d+)/gim,
          source: 'Juniper',
        },
        swg: {
          regexp: /(swg\d+)/gim,
          source: 'IBM',
        },
        st1: {
          regexp: /securitytracker\.com\/id\?(\d+)/im,
          source: 'SecurityTracker',
          cb: match => `ST-${match[1]}`,
        },
        st2: {
          regexp: /securitytracker\.com\/.+\/(\d+)\.html/im,
          source: 'SecurityTracker',
          cb: match => `ST-${match[1]}`,
        },
        osvdb: {
          regexp: /osvdb.org\/(\d+)/im,
          cb: () => null, // игнорируем, т.к. эта база уязвимостей больше не работает
        },
      };

      if (uri.host) {
        let referenceItem;

        for (const key in config) {
          const curConfig = config[key];

          const match = link.match(curConfig.regexp);
          if (match) {
            const cb = curConfig.cb || defaultCb;

            referenceItem = {
              ref_id: cb(match),
              source: curConfig.source,
              ref_url: link,
            };
            continue;
          }
        }

        referenceItem = referenceItem || {
          ref_id: link,
          source: uri.host,
          ref_url: link,
        };

        if (referenceItem.ref_id !== null) {
          reference.push(referenceItem);
        }
      }

      return reference;
    }, []);
}

/**
 * Парсит параметры интерфейсов из xml отчета
 * @param {Object} vuln - часть отчета из xml-stream
 * @returns {Object}
 */
// function parseInterfaces(vuln) {
//   const ifsItem = {
//     name: vuln.param,
//     address: [],
//   };
//
//   vuln.param_list.forEach((param) => {
//     param.table.forEach((table) => {
//       const tableName = table.$.name;
//       table.body.forEach((body) => {
//         body.row.forEach((row) => {
//           if (tableName === 'GennetConnNew') {
//             // linux-сервер
//             if (row.field[0].$text === 'MAC:') {
//               ifsItem.mac = row.field[1].$text;
//             }
//
//             if (row.field[0].$text === 'Address:') {
//               const match = String(row.field[1].$text).match(newIpAndMaskRegExp);
//
//               if (match) {
//                 ifsItem.address.push({
//                   ip: match[1],
//                   mask: ipUtils.fromPrefixLen(match[2]),
//                   family: 'ipv4',
//                 });
//               }
//             }
//           } else if (tableName === 'Gen') {
//             // cisco
//             row.field.forEach((field) => {
//               if (typeof field.$text !== 'string') return;
//               const id = parseInt(field.$.id, 10);
//               if (id === 5) {
//                 ifsItem.mac = field.$text.replace(/(.{2})/g, '$1:').slice(0, -1);
//               }
//
//               if (id === 2) {
//                 const match = String(field.$text).match(ciscoIpAndMaskRegExp);
//
//                 if (match) {
//                   ifsItem.address.push({
//                     ip: match[1],
//                     mask: ipUtils.fromPrefixLen(match[2]),
//                     family: 'ipv4',
//                   });
//                 }
//               }
//             });
//           } else {
//             const rowLength = row.field.length;
//             row.field.forEach((field) => {
//               const idOffset = rowLength > 9 ? 1 : 0;
//               const id = Number(field.$.id);
//
//               if (id === 4 + idOffset) {
//                 ifsItem.mac = field.$text;
//               }
//
//               if (id === 6 + idOffset) {
//                 const match = String(field.$text).match(ipAndMaskRegExp);
//
//                 if (match) {
//                   ifsItem.address.push({
//                     ip: match[1],
//                     mask: match[2],
//                     family: 'ipv4',
//                   });
//                 }
//               }
//             });
//           }
//         });
//       });
//     });
//   });
//
//   return ifsItem;
// }

/**
 * Парсит пользователей из xml отчета
 * @param {Object} vuln - часть отчета из xml-stream
 * @returns {Object}
 */
// function parseUsers(vuln) {
//   const userItem = {
//     login: vuln.$.param,
//   };
//
//   vuln.param_list.forEach((param) => {
//     param.table.forEach((table) => {
//       table.body.forEach((body) => {
//         body.row.forEach((row) => {
//           row.field.forEach((field) => {
//             const id = parseInt(field.$.id, 10);
//
//             if (id === 2) {
//               userItem.fio = field.text;
//             }
//           });
//         });
//       });
//     });
//   });
//
//   return userItem;
// }

/**
 * Парсит уязвимости
 * @see RVN-4043
 * @param {Object[]} vulners - Массив уязвимостей из отчета
 * @param {Object} host
 * @param {Number} port
 * @param {String} protocol
 * @return {Object}
 */
function parseVulners(vulners, host, port, protocol) {
  const vulnerabilities = [];
  const users = [];
  const interfaces = [];
  let mac;

  vulners.forEach((vulner) => {
    const id = Number(vulner.$.id);
    const level = Number(vulner.$.level);

    if (id) {
      // Уязвимости
      let vuln = { id, level };
      if (port > 0) {
        vuln = Object.assign(vuln, { port, protocol, isNetworkVulnerability: true });
      }

      vulnerabilities.push(vuln);

      // MAC-адреса
      if (id === 180245 && !host.mac) {
        mac = vulner.param.toLowerCase();
      }

      // Сетевые интерфейсы
      if (id === 4424673 || id === 425336) {
        const ifsItem = parseInterfaces(vulner);
        if (ifsItem.address.length > 0) {
          interfaces.push(ifsItem);
        }
      }

      // Пользователи
      if (id === 425318) {
        users.push(parseUsers(vulner));
      }
    }
  });

  return {
    users, vulnerabilities, interfaces, mac,
  };
}

function parseNetworkDeviceSoft(data) {
  function getNetworkDeviceInterfacesRaw(vulns) {
    const interfacesTable = vulns.reduce((accumulator, item) => {
      const el = _.get(item, 'param_list[0].table[0].body');
      if (el && item.$.id === '425336') {
        accumulator.push(el);
      }

      return accumulator;
    }, []);

    const deviceIfs = [];
    for (const ifs of interfacesTable) {
      for (const ifsRow of ifs) {
        const ifsRaw = {};

        for (const [index, field] of ifsRow.row[0].field.entries()) {
          const text = field.$text;
          if (text) {
            switch (index) {
              case 1:
                ifsRaw.address = text;
                break;
              case 4:
                ifsRaw.mac = text;
                break;
            }
          }
        }

        if (ifsRaw) {
          deviceIfs.push(ifsRaw);
        }
      }
    }

    return deviceIfs;
  }

  function formatCiscoInterfaces(ifs) {
    return ifs.reduce((accumulator, item) => {
      if (item.address) {
        const [ip, mask] = item.address.split('/');

        if (ipUtils.isV4Format(ip) && !['127.0.0.1', '::1'].includes(ip)) {
          accumulator.push({
            mac: item.mac.match(/\w{1,2}/g).join(':'),
            address: [{
              ip,
              mask: ipUtils.fromPrefixLen(mask),
              family: 'ipv4',
            }],
          });
        }
      }

      return accumulator;
    }, []);
  }

  function getNetworkDeviceUsers(vulns) {
    return vulns.reduce((accumulator, item) => {
      if (item.$.id === '411402') {
        accumulator.push(item.param);
      }

      return accumulator;
    }, []);
  }

  function getNetworkDeviceFirmware(vulns) {
    const firmwareVuln = vulns.find(item => (item.$.id === '411401'));
    const firmwareName = _.get(firmwareVuln, 'param_list[0].table[0].body[0].row[0].field[0].$text');
    const firmwareVersion = _.get(firmwareVuln, 'param_list[0].table[0].body[0].row[0].field[1].$text');

    if (firmwareName || firmwareVersion) {
      return {
        name: firmwareName,
        version: firmwareVersion,
      };
    }
    return undefined;
  }

  const { name: os, version, vulners } = data;
  const networkDeviceData = vulners.vulner;

  if (!networkDeviceData || networkDeviceData.length === 0) {
    return { error: 'parseNetworkDeviceData: Empty data!' };
  }

  const ifsRaw = getNetworkDeviceInterfacesRaw(networkDeviceData);
  const ifs = formatCiscoInterfaces(ifsRaw);

  const users = getNetworkDeviceUsers(networkDeviceData);
  const firmware = getNetworkDeviceFirmware(networkDeviceData);

  return {
    os,
    ifs,
    users,
    firmware,
  };
}

function parseHostSoft(data, os) {
  function getWindowsNetworkAdapterData(vuln) {
    const networkInterface = {
      name: vuln.param,
      address: [],
    };
    const MAC_AND_ADDRESS_KEYS = [4, 5, 6, 7];
    const ifsData = formatSingleDimentionalParamListTable(vuln.param_list);

    if (ifsData && ifsData.length) {
      for (const ifs of ifsData) {
        for (const key of MAC_AND_ADDRESS_KEYS) {
          const value = ifs[key];

          const macAddressMatch = value.match(macAddressRegExp);
          if (macAddressMatch) {
            networkInterface.mac = value;
            continue;
          }

          const ipAddressMatch = value.match(ipAndMaskRegExp);
          if (ipAddressMatch && ipUtils.isV4Format(ipAddressMatch[1])) {
            networkInterface.address.push({
              ip: ipAddressMatch[1],
              mask: ipAddressMatch[2],
              family: 'ipv4',
            });
          }
        }
      }
    }


    // vuln.param_list.forEach((param) => {
    //   param.table.forEach((table) => {
    //     table.body.forEach((body) => {
    //       body.row.forEach((row) => {
    //         row.field.forEach((field) => {
    //           const idOffset = row.field.length > 9 ? 1 : 0;
    //           const id = Number(field.$.id);
    //           const value = String(field.$text) || '';
    //
    //           if ((id === 4 + idOffset || id === 5 + idOffset) && value.match(macAddressRegExp)) {
    //             networkInterface.mac = value;
    //           }
    //
    //           if ((id === 6 + idOffset || id === 7 + idOffset)) {
    //             const match = value.match(ipAndMaskRegExp);
    //
    //             if (match && ipUtils.isV4Format(match[1])) {
    //               networkInterface.address.push({
    //                 ip: match[1],
    //                 mask: match[2],
    //                 family: 'ipv4',
    //               });
    //             }
    //           }
    //         });
    //       });
    //     });
    //   });
    // });

    return networkInterface;
  }

  function getWindowsUserData(vuln) {
    const LOGIN_KEY = 1;
    const SID_KEY = 4;
    const userData = formatSingleDimentionalParamListTable(vuln.param_list, true);

    return {
      login: userData[LOGIN_KEY],
      name: userData[LOGIN_KEY],
      sid: userData[SID_KEY],
    };
  }

  function getWindowsSoftware(vuln) {
    const VERSION_KEY = 1;
    const softData = formatSingleDimentionalParamListTable(vuln.param_list, true);

    return {
      name: vuln.param,
      version: softData[VERSION_KEY],
    };
  }

  function getLinuxNetworkAdapterData(vuln) {
    const ADDRESS_KEY = 4;
    const MAC_KEY = 5;

    const ifsData = formatTwoDimentionalParamListTable(vuln.param_list, 1);

    const match = ifsData[ADDRESS_KEY].match(newIpAndMaskRegExp);

    if (match) {
      return {
        name: vuln.param,
        mac: ifsData[MAC_KEY],
        address: [{
          ip: match[1],
          mask: ipUtils.fromPrefixLen(match[2]),
          family: 'ipv4',
        }],
      };
    }

    return undefined;
  }

  function getLinuxSoftware(vuln) {
    const NAME_KEY = 1;
    const VERSION_KEY = 2;
    const softData = formatSingleDimentionalParamListTable(vuln.param_list);

    return softData.map(item => ({
      name: item[NAME_KEY],
      version: item[VERSION_KEY],
    }));
  }

  function getLinuxUserData(vuln) {
    return {
      name: vuln.param,
      login: vuln.param,
    };
  }

  const ifs = [];
  const users = [];
  const ports = [];
  const vulns = {};
  let software = [];

  for (const item of data) {
    const {
      name, version, vulners, port, protocol,
    } = item;
    const { id } = item.$;

    if (port > 0) {
      ports.push(port);
    }

    if (vulners && vulners.vulner) {
      for (const vuln of vulners.vulner) {
        const { id: vulnerId, level } = vuln.$;
        let user;
        let soft;

        if (vulnerId === '4424673') {
          // сетевые интерфейсы
          const networkInterface = os.includes('Windows') ?
            getWindowsNetworkAdapterData(vuln) :
            getLinuxNetworkAdapterData(vuln);

          if (networkInterface && networkInterface.address && networkInterface.address.length) {
            ifs.push(networkInterface);
          }
        } else if (vulnerId === '401005') {
          // пользователи Windows
          user = getWindowsUserData(vuln);
        } else if (vulnerId === '425318') {
          // пользователи Linux
          user = getLinuxUserData(vuln);
        } else if (vulnerId === '401000') {
          // софт Windows
          soft = getWindowsSoftware(vuln);
        } else if (vulnerId === '175492') {
          // софт Linux
          soft = getLinuxSoftware(vuln);
        } else {
          vulns[vulnerId] = {
            port,
            protocol,
          };
        }

        if (soft) {
          if (Array.isArray(soft)) {
            software = [
              ...software,
              ...soft,
            ];
          } else {
            software.push(soft);
          }
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
  };
}

function parseSNMPData(data) {
  function parseNetworkAddresses(vuln) {
    const IP_KEY = 1;
    const INTERFACE_ID_KEY = 2;
    const NETMASK_KEY = 3;

    const addresses = formatSingleDimentionalParamListTable(vuln.param_list);

    if (addresses) {
      return addresses.map(item => ({
        ip: item[IP_KEY],
        mask: item[NETMASK_KEY],
        interfaceId: item[INTERFACE_ID_KEY],
      }));
    }

    return undefined;
  }

  function parseNetworkInterfaces(vuln) {
    const ID_KEY = 1;
    const MAC_KEY = 6;

    const interfaces = formatSingleDimentionalParamListTable(vuln.param_list);

    if (interfaces) {
      return interfaces.map(item => ({
        id: item[ID_KEY],
        mac: item[MAC_KEY],
      }));
    }

    return undefined;
  }

  function parseSystemInformation(vuln) {
    const NAME_KEY = 4;

    const info = formatSingleDimentionalParamListTable(vuln.param_list, true);

    return { name: info[NAME_KEY] };
  }

  let addresses = [];
  let interfaces = [];
  let name = '';

  for (const vuln of data.vulners.vulner) {
    switch (vuln.$.id) {
      case '8167':
        interfaces = parseNetworkInterfaces(vuln);
        break;
      case '8168':
        ({ name } = parseSystemInformation(vuln));
        break;
      case '8169':
        addresses = parseNetworkAddresses(vuln);
        break;
    }
  }

  const ifs = [];

  for (const address of addresses) {
    const networkInterface = interfaces.find(item => item.id === address.interfaceId);

    if (networkInterface) {
      delete address.interfaceId;

      ifs.push({
        mac: networkInterface.mac,
        address: [address],
      });
    }
  }

  return {
    ifs,
    name,
  };
}

function filterNetworkinterfaces(interfaces) {
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
 * @param {Date} lastRun - дата последнего запуска
 */
module.exports = function (inputStream, lastRun, cb) {
  const xml = new XmlStream(inputStream);

  xml.collect('scan_objects > soft');
  // xml.collect('scan_objects > soft > vulners');
  xml.collect('scan_objects > soft > vulners > vulner');
  xml.collect('scan_objects > soft > vulners > vulner > param_list');
  xml.collect('scan_objects > soft > vulners > vulner > param_list > table');
  xml.collect('scan_objects > soft > vulners > vulner > param_list > table > body');
  xml.collect('scan_objects > soft > vulners > vulner > param_list > table > body > row');
  xml.collect('scan_objects > soft > vulners > vulner > param_list > table > body > row > field');

  // в результатах всего один ряд значений, так что остальное нас не интересует
  xml.collect('hardware > device');
  xml.collect('hardware > device > param_list > table > body > row > field');

  xml.collect('content > vulners > vulner');
  xml.collect('content > vulners > vulner > global_id');

  // undocumented feature, second parameter preserves whitespaces
  xml.preserve('content > vulners > vulner > description', true);

  const xmlSoftware = [];
  const uniqueVulns = {};
  let hosts = [];
  let software = [];
  let vulns = {};
  let ports = [];
  let users = [];
  let ifs = [];
  let host = {};
  let hardware = {};
  let firmware = {};
  let os = '';
  let name = '';

  xml.on('startElement: host', () => {
    xmlSoftware.length = 0;
    software.length = 0;
    ifs.length = 0;
    ports.length = 0;
    users.length = 0;
    vulns = {};
    host = {};
    hardware = {};
    firmware = {};
    os = '';
    name = '';
  });

  xml.on('endElement: hardware', (node) => {
    // получаем серийный номер материнской платы
    const serialNode = node.device.find(item => item.$.id === '425302');
    hardware = {
      serial: _.get(serialNode, 'param_list.table.body.row.field[0].$text'),
    };
  });

  xml.on('endElement: scan_objects > soft', (node) => {
    // Программное обеспечение
    const { name, version } = node;
    const port = node.$.port && Number(node.$.port);
    let protocol = node.$.protocol && Number(node.$.protocol);

    switch (protocol) {
      case 6:
        protocol = 'tcp';
        break;
      case 17:
        protocol = 'udp';
        break;
    }

    xmlSoftware.push({
      ...node,
      port,
      protocol,
    });

    // Список открытых портов
    if (port > 0) {
      ports.push(port);
    }
  });

  xml.on('endElement: host', (node) => {
    const {
      fqdn,
      netbios,
      stop_time: stopTime,
      start_time: startTime,
      host_uid: maxpatrolUid,
    } = node.$;
    const stop = Number(new Date(stopTime));
    if (stop && lastRun && stop < lastRun) {
      return true;
    }

    const snmpData = xmlSoftware.find(item => item.name === 'SNMP');
    const osData = xmlSoftware.find(item => item.name === 'Operating System');
    if (osData) {
      os = osData.version;
    }

    let softData = {};

    // если хост является сетевым оборудованием
    if (xmlSoftware.length === 1 && ['Cisco IOS', 'Juniper JUNOS', 'Cisco ASA'].includes(xmlSoftware[0].name)) {
      softData = parseNetworkDeviceSoft(xmlSoftware[0]);
    } else {
      softData = parseHostSoft(xmlSoftware, os);
    }

    if ((!softData.ifs || softData.ifs.length === 0) &&
      (snmpData && snmpData.vulners && snmpData.vulners.vulner && snmpData.vulners.vulner.length)) {
      softData = parseSNMPData(snmpData);
    }

    ({
      ifs,
      os,
      users,
      firmware,
      name,
      software,
      vulns,
    } = softData);

    if (softData.ports && softData.ports.length) {
      ports = [...ports, ...softData.ports];
    }

    ifs = filterNetworkinterfaces(ifs);
    if (!ifs || ifs.length === 0) {
      return true;
    }

    host = {
      name: fqdn || netbios || name,
      start_time: startTime,
      stop_time: stopTime,
      updated_at: new Date(stopTime).toUTCString(),
      maxpatrolUid,
      os,
      ports,
      users,
      hardware,
      firmware,
      software,
      ifs,
      vulns,
    };

    hosts.push(host);
  });

  xml.on('endElement: content > vulners > vulner', (el) => {
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

    if (!globalId || globalId.length === 0) {
      return;
    }

    const level = Number(cvss.$.base_score) / 2;
    const vulnDescription = description.$text || shortDescription.$text || '';
    const vuln = {
      description: vulnDescription.replace(/  +/g, ' '),
      name: title,
      remediation,
      uid: $.id,
      reference: parseReferenceLinks(links),
      level: level === 0 ? 1 : level,
    };

    if (vuln.uid) {
      uniqueVulns[vuln.uid] = vuln;
    }
  });

  xml.on('error', (err) => {
    console.dir(err, { depth: null, colors: true });
  });

  xml.on('end', () => {
    hosts = hosts.map((item) => {
      const vulnerabilities = [];
      if (item.vulns) {
        for (const key in item.vulns) {
          const vuln = item.vulns[Number(key)];
          const uniqueVuln = uniqueVulns[Number(key)];

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

      delete item.vulns;

      return {
        ...item,
        vulnerabilities,
      };


      // if (host.vulnerabilities) {
      //   const result = [];
      //
      //   host.vulnerabilities.forEach((vuln) => {
      //     let { level, id } = vuln;
      //
      //     if (level !== 0 && vulnerabilitiesDesc[id]) {
      //       const item = Object.assign({}, vulnerabilitiesDesc[id]);
      //
      //       item.level_id = level < 5 ? ++level : level;
      //
      //       if (vuln.isNetworkVulnerability) {
      //         item.isNetworkVulnerability = true;
      //         item.port = vuln.port;
      //         item.protocol = vuln.protocol;
      //       }
      //
      //       result.push(item);
      //     }
      //   });
      //
      //   host.vulnerabilities = result;
      // }
    });

    cb(null, hosts);
  });
};
