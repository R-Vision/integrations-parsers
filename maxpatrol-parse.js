'use strict';

const XmlStream = require('xml-stream');

const url = require('url');
const _ = require('lodash');
const ip = require('ip');

/**
 * Получает имя домена из строки
 * @see RVN-4024
 * @param {String} value - строка с именем домена
 * @returns {String}
 */
function getDomainName(value) {
  if (!value || ip.isV4Format(value) || ip.isV6Format(value)) return null;

  let domain = String(value).split('.');
  const l = domain.length;

  if (l === 1) return null;

  if (l > 2) {
    domain = domain.splice(l - 2, l);
  }

  return domain.join('.');
}

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

/**
 * По ссылке на уязвимость получает название БД с уязвимостями
 * @param {String[]} links - массив ссылок на  уязвимость
 * @returns {String[]}
 */
function parseReferenceLinks(links) {
  // TODO: I should probably refactor this mess :/
  return links.reduce((reference, link) => {
    const uri = url.parse(link);

    const cve = link.match(/(CVE-\d+-\d+)/gim);
    const rhsa = link.match(/(RHSA-\d+-\d+)/gim);
    const ms = link.match(/(ms\d+-\d+)/gim);
    const bid = link.match(/(bid\/\d+)/gim);
    const xfdb = link.match(/(xfdb\/\d+)/gim);
    const dsa = link.match(/(dsa-\d+)/gim);
    const usn = link.match(/(usn-\d+-\d+)/gim);
    const mdksa = link.match(/(MDKSA-\d+:\d+)/gim);
    const asa = link.match(/(ASA-\d+-\d+)/gim);
    const glsa = link.match(/(glsa-\d+-\d+)/gim);
    const esx = link.match(/(esx-\d+)/gim);
    const rpl = link.match(/(RPL-\d+)/gim);
    const vmsa = link.match(/(VMSA-\d+-\d+)/gim);
    const jsa = link.match(/(JSA\d+)/gim);
    const swg = link.match(/(swg\d+)/gim);
    const st1 = link.match(/securitytracker\.com\/id\?(\d+)/im);
    const st2 = link.match(/securitytracker\.com\/.+\/(\d+)\.html/im);
    const osvdb = link.match(/osvdb.org\/(\d+)/im);

    if (uri.host) {
      if (cve) {
        reference.push({
          ref_id: cve.toString().toUpperCase(),
          source: 'CVE',
          ref_url: link,
        });
      } else if (rhsa) {
        reference.push({
          ref_id: rhsa.toString().toUpperCase(),
          source: 'RedHat',
          ref_url: link,
        });
      } else if (ms) {
        reference.push({
          ref_id: ms.toString().toUpperCase(),
          source: 'Microsoft',
          ref_url: link,
        });
      } else if (bid) {
        reference.push({
          ref_id: bid.toString().toUpperCase(),
          source: 'SecurityFocus',
          ref_url: link,
        });
      } else if (xfdb) {
        reference.push({
          ref_id: xfdb.toString().toUpperCase(),
          source: 'X-Force',
          ref_url: link,
        });
      } else if (dsa) {
        reference.push({
          ref_id: dsa.toString().toUpperCase(),
          source: 'Debian',
          ref_url: link,
        });
      } else if (usn) {
        reference.push({
          ref_id: usn.toString().toUpperCase(),
          source: 'Ubuntu',
          ref_url: link,
        });
      } else if (mdksa) {
        reference.push({
          ref_id: mdksa.toString().toUpperCase(),
          source: 'Mandriva',
          ref_url: link,
        });
      } else if (asa) {
        reference.push({
          ref_id: asa.toString().toUpperCase(),
          source: 'Avaya',
          ref_url: link,
        });
      } else if (glsa) {
        reference.push({
          ref_id: glsa.toString().toUpperCase(),
          source: 'Gentoo',
          ref_url: link,
        });
      } else if (esx) {
        reference.push({
          ref_id: esx.toString().toUpperCase(),
          source: 'VMware',
          ref_url: link,
        });
      } else if (rpl) {
        reference.push({
          ref_id: rpl.toString().toUpperCase(),
          source: 'Rpath',
          ref_url: link,
        });
      } else if (vmsa) {
        reference.push({
          ref_id: vmsa.toString().toUpperCase(),
          source: 'VMware',
          ref_url: link,
        });
      } else if (jsa) {
        reference.push({
          ref_id: jsa.toString().toUpperCase(),
          source: 'Juniper',
          ref_url: link,
        });
      } else if (swg) {
        reference.push({
          ref_id: swg.toString().toUpperCase(),
          source: 'IBM',
          ref_url: link,
        });
      } else if (st1) {
        reference.push({
          ref_id: `ST-${st1[1]}`,
          source: 'SecurityTracker',
          ref_url: link,
        });
      } else if (st2) {
        reference.push({
          ref_id: `ST-${st2[1]}`,
          source: 'SecurityTracker',
          ref_url: link,
        });
      } else if (osvdb) {
        // игнорируем, т.к. эта база уязвимостей больше не работает
      } else {
        reference.push({
          ref_id: link,
          source: uri.host,
          ref_url: link,
        });
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
function parseInterfaces(vuln) {
  const ifsItem = {
    name: vuln.param,
    address: [],
  };

  const ipAndMaskRegExp = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/;
  const newIpAndMaskRegExp = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\(\/(\d{1,2})\)/;
  const ciscoIpAndMaskRegExp = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})/;

  vuln.param_list.forEach((param) => {
    param.table.forEach((table) => {
      const tableName = table.$.name;
      table.body.forEach((body) => {
        body.row.forEach((row) => {
          if (tableName === 'GennetConnNew') {
            // linux-сервер
            if (row.field[0].$text === 'MAC:') {
              ifsItem.mac = row.field[1].$text;
            }

            if (row.field[0].$text === 'Address:') {
              const match = String(row.field[1].$text).match(newIpAndMaskRegExp);

              if (match) {
                ifsItem.address.push({
                  ip: match[1],
                  mask: ip.fromPrefixLen(match[2]),
                  family: 'ipv4',
                });
              }
            }
          } else if (tableName === 'Gen') {
            // cisco
            row.field.forEach((field) => {
              const id = parseInt(field.$.id, 10);
              if (id === 5) {
                ifsItem.mac = field.$text.replace(/(.{2})/g, '$1:').slice(0, -1);
              }

              if (id === 2) {
                const match = String(field.$text).match(ciscoIpAndMaskRegExp);

                if (match) {
                  ifsItem.address.push({
                    ip: match[1],
                    mask: ip.fromPrefixLen(match[2]),
                    family: 'ipv4',
                  });
                }
              }
            });
          } else {
            const rowLength = row.field.length;
            row.field.forEach((field) => {
              const idOffset = rowLength > 9 ? 1 : 0;
              const id = parseInt(field.$.id, 10);

              if (id === 4 + idOffset) {
                ifsItem.mac = field.$text;
              }

              if (id === 6 + idOffset) {
                const match = String(field.$text).match(ipAndMaskRegExp);

                if (match) {
                  ifsItem.address.push({
                    ip: match[1],
                    mask: match[2],
                    family: 'ipv4',
                  });
                }
              }
            });
          }
        });
      });
    });
  });

  return ifsItem;
}

/**
 * Парсит пользователей из xml отчета
 * @param {Object} vuln - часть отчета из xml-stream
 * @returns {Object}
 */
function parseUsers(vuln) {
  const userItem = {
    login: vuln.$.param,
  };

  vuln.param_list.forEach((param) => {
    param.table.forEach((table) => {
      table.body.forEach((body) => {
        body.row.forEach((row) => {
          row.field.forEach((field) => {
            const id = parseInt(field.$.id, 10);

            if (id === 2) {
              userItem.fio = field.text;
            }
          });
        });
      });
    });
  });

  return userItem;
}

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

  return { users, vulnerabilities, interfaces, mac };
}

/**
 * Парсит xml отчет из MaxPatrol
 * @param {Stream} stream - readable поток с отчетом
 * @param {Date} lastRun - дата последнего запуска
 * @param {Function} cb - callback. вызывается после завершения работы функции
 */
module.exports = function(stream, lastRun, cb) {
  const hosts = [];
  const vulnerabilitiesDesc = {};

  const xml = new XmlStream(stream);

  xml.collect('scan_objects > soft > vulners > vulner');
  xml.collect('scan_objects > soft > vulners > vulner > param_list');
  xml.collect('scan_objects > soft > vulners > vulner > param_list > table');
  xml.collect('scan_objects > soft > vulners > vulner > param_list > table > body');
  xml.collect('scan_objects > soft > vulners > vulner > param_list > table > body > row');
  xml.collect('scan_objects > soft > vulners > vulner > param_list > table > body > row > field');

  xml.collect('content > vulners > vulner');

  // undocumented feature, second parameter preserves whitespaces
  xml.preserve('content > vulners > vulner > description', true);

  let software = {};
  let interfaces = [];
  let ports = [];
  let users = [];
  let vulnerabilities = [];
  let host = {};

  xml.on('startElement: host', () => {
    software = {};
    interfaces = [];
    ports = [];
    users = [];
    vulnerabilities = [];
    host = {};
  });

  xml.on('endElement: scan_objects > soft', (soft) => {
    // Программное обеспечение
    const name = soft.name;
    const version = soft.version;
    const port = soft.$.port && parseInt(soft.$.port, 10);
    let protocol = soft.$.protocol && parseInt(soft.$.protocol, 10);

    // Список открытых портов
    if (port > 0 && protocol > 0) {
      if (protocol === 6) {
        protocol = 'tcp';
      } else if (protocol === 17) {
        protocol = 'udp';
      }
    }

    if (!_.isEmpty(name) && !_.isEmpty(version) && blockedSoftware.indexOf(name) === -1) {
      software[name + version] = { name, version };
    }

    if (soft.vulners && soft.vulners.vulner) {
      const data = parseVulners(soft.vulners.vulner, host, port, protocol);

      interfaces.push(...data.interfaces);
      vulnerabilities.push(...data.vulnerabilities);
      users.push(...data.users);
      if (data.mac) {
        host.mac = data.mac;
      }
    }

    if (port > 0) {
      ports.push({ port, protocol });
    }
  });

  xml.on('endElement: host', (node) => {
    const stop = Number(new Date(node.$.stop_time));
    if (stop && lastRun && stop < lastRun) return true;

    host = {
      address: node.$.ip,
      ip: node.$.ip,
      name: node.$.netbios || node.$.fqdn,
      start_time: node.$.start_time,
      stop_time: node.$.stop_time,
      updated_at: new Date(node.$.stop_time).toUTCString(),
      domain_workgroup: getDomainName(node.$.fqdn),
    };

    if (interfaces.length > 0) {
      host.ifs = interfaces;
    }

    if (ports.length > 0) {
      host.ports = _.values(_.indexBy(ports, 'port'));
    }

    if (vulnerabilities.length > 0) {
      host.vulnerabilities = vulnerabilities.slice(0);
    }

    if (!_.isEmpty(software)) {
      host.software = _.values(software);
    }

    if (users.length > 0) {
      host.users = users;
    }

    hosts.push(host);
  });

  xml.on('endElement: content > vulners > vulner', (el) => {
    const description = el.description.$text || el.short_description.$text || '';
    const vuln = {
      description: description.replace(/  +/g, ' '),
      name: el.title,
      remediation: el.how_to_fix,
      uid: el.$.id,
      reference: parseReferenceLinks(el.links.replace(/[\n\t\r]/g, ' ').split(' ')),
    };

    if (vuln.uid) {
      vulnerabilitiesDesc[vuln.uid] = vuln;
    }
  });

  xml.on('error', (err) => {
    console.dir(err, { depth: null, colors: true });
    cb(err);
  });

  xml.on('end', () => {
    hosts.forEach((host) => {
      if (host.vulnerabilities) {
        const result = [];

        host.vulnerabilities.forEach((vuln) => {
          const id = vuln.id;
          let { level } = vuln;

          if (level !== 0 && vulnerabilitiesDesc[id]) {
            const item = vulnerabilitiesDesc[id];

            item.level_id = level < 5 ? ++level : level;

            if (vuln.isNetworkVulnerability) {
              item.isNetworkVulnerability = true;
              item.port = vuln.port;
              item.protocol = vuln.protocol;
            }

            result.push(item);
          }
        });

        host.vulnerabilities = result;
      }
    });

    cb(null, hosts);
  });
};
