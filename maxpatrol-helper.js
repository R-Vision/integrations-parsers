/* eslint-disable no-restricted-syntax,no-continue */

'use strict';

const url = require('url');
const _ = require('lodash');
const ipUtils = require('ip');

const ipAndMaskRegExp = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/;
const newIpAndMaskRegExp = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\(\/(\d{1,2})\)/;
const macAddressRegExp = /^([0-9a-fA-F]{2}[:.-]?){5}[0-9a-fA-F]{2}$/i;

/**
 * Получает имя домена из строки
 * @see RVN-4024
 * @param {String} value - строка с именем домена
 * @returns {String}
 */
function getDomainName(value) {
  if (!value || ipUtils.isV4Format(value) || ipUtils.isV6Format(value)) return null;

  const domain = String(value).split('.');
  const l = domain.length;

  if (l > 2) {
    return domain.splice(l - 2, l).join('.');
  }

  return null;
}

/**
 * Конвертируем данные из xml-таблицы в объект если в каждом field только одно значение.
 * @param {Object} paramList - корень таблицы
 * @param {Boolean} returnFirstItem - в зависимости от флага возвращаем массив или объект
 * @returns {*}
 */
function formatSingleDimensionParamListTable(paramList, returnFirstItem) {
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
 * Конвертируем данные из xml-таблицы в объект если в каждом field несколько значений.
 * @param {Object} paramList - корень таблицы
 * @param {Number} valueId - указывает field, в котором интересующие значения
 * @returns {*}
 */
function formatTwoDimensionParamListTable(paramList, valueId) {
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

// Сетевые адаптеры
/**
 * Получаем данные сетевого адаптера Windows
 * @param {Object} vuln
 * @returns {Object}
 */
function getWindowsNetworkAdapterData(vuln) {
  const networkInterface = {
    name: vuln.param,
    address: [],
  };

  // данные ip и маски могут быть в  4 или 5 ячейке, а mac - в 6 или 7
  const MAC_AND_ADDRESS_KEYS = [4, 5, 6, 7];
  const ifsData = formatSingleDimensionParamListTable(vuln.param_list);

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

  return networkInterface;
}

/**
 * Получаем данные сетевого адаптера Linux
 * @param {Object} vuln
 * @returns {*}
 */
function getLinuxNetworkAdapterData(vuln) {
  const ADDRESS_KEY = 4;
  const MAC_KEY = 5;

  const ifsData = formatTwoDimensionParamListTable(vuln.param_list, 1);

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

/**
 * Получаем данные сетевого адаптера сетевого устройства
 * @param {Object} vuln
 * @returns {*}
 */
function getNetworkDeviceNetworkAdapterData(vuln) {
  const ADDRESS_AND_MASK_KEY = 2;
  const MAC_KEY = 5;

  const info = formatSingleDimensionParamListTable(vuln.param_list, true);

  if (!info[ADDRESS_AND_MASK_KEY]) {
    return undefined;
  }

  const [ip, mask] = info[ADDRESS_AND_MASK_KEY].split('/');
  const mac = info[MAC_KEY] ? info[MAC_KEY].match(/\w{1,2}/g).join(':') : undefined;

  return {
    mac,
    address: [{
      ip,
      mask: ipUtils.fromPrefixLen(mask),
      family: 'ipv4',
    }],
  };
}

/**
 * В зависимости от названия таблицы получаем данные сетевого адаптера
 * @param {Object} vuln
 * @returns {Object}
 */
function getNetworkInterfaceData(vuln) {
  const tableName = _.get(vuln, 'param_list[0].table[0].$.name');

  return tableName === 'GennetConnNew' ?
    getLinuxNetworkAdapterData(vuln) :
    getWindowsNetworkAdapterData(vuln);
}

// Софт
/**
 * Получаем данные софта Windows
 * @param {Object} vuln
 * @returns {{name: String, version: String}}
 */
function getWindowsSoftwareData(vuln) {
  const VERSION_KEY = 1;
  const softData = formatSingleDimensionParamListTable(vuln.param_list, true);

  return {
    name: vuln.param,
    version: softData[VERSION_KEY],
  };
}

/**
 * Получаем данные софта Linux в массиве
 * @param {Object} vuln
 * @returns {[{ name:string, version:String }]}
 */
function getLinuxSoftwareData(vuln) {
  const NAME_KEY = 1;
  const VERSION_KEY = 2;
  const softData = formatSingleDimensionParamListTable(vuln.param_list);

  return softData.map(item => ({
    name: item[NAME_KEY],
    version: item[VERSION_KEY],
  }));
}

// Пользователи
/**
 * Получаем данные пользователей Windows
 * @param {Object} vuln
 * @returns {{name: String, login: String}}
 */
function getWindowsUserData(vuln) {
  const LOGIN_KEY = 1;
  const userData = formatSingleDimensionParamListTable(vuln.param_list, true);

  return {
    login: userData[LOGIN_KEY],
    name: userData[LOGIN_KEY],
  };
}

/**
 * Получаем данные пользователей Linux или сетевого оборудования
 * @param {Object} vuln
 * @returns {{name: String, login: String}}
 */
function getNetworkDeviceOrLinuxUserData(vuln) {
  return {
    name: vuln.param,
    login: vuln.param,
  };
}

// Прочее
/**
 * Получаем данные прошивки сетевого устройства
 * @param {Object} vuln
 * @returns {{name: String, version: String}}
 */
function getNetworkDeviceFirmwareData(vuln) {
  const FIRMWARE_NAME_KEY = 1;
  const FIRMWARE_VERSION_KEY = 2;
  const info = formatSingleDimensionParamListTable(vuln.param_list, true);

  return {
    name: info[FIRMWARE_NAME_KEY],
    version: info[FIRMWARE_VERSION_KEY],
  };
}

/**
 * Получаем серийные номера сетевого устройства
 * @param {Object} node
 * @returns {{modelNumber: String, sn: String}}
 */
function getSerialNumbers(node) {
  const MOTHERBOARD_SERIAL_KEY = 9;
  const MODEL_NUMBER_KEY = 12;

  const info = formatSingleDimensionParamListTable(node.param_list, true);

  return {
    sn: info[MOTHERBOARD_SERIAL_KEY],
    modelNumber: info[MODEL_NUMBER_KEY],
  };
}

// SNMP
/**
 * Получаем сетевые адреса из данных SNMP
 * @param {Object} vuln
 * @returns {*}
 */
function getSNMPNetworkAddresses(vuln) {
  const IP_KEY = 1;
  const INTERFACE_ID_KEY = 2;
  const NETMASK_KEY = 3;

  const addresses = formatSingleDimensionParamListTable(vuln.param_list);

  if (addresses) {
    return addresses.map(item => ({
      ip: item[IP_KEY],
      mask: item[NETMASK_KEY],
      interfaceId: item[INTERFACE_ID_KEY],
    }));
  }

  return undefined;
}

/**
 * Получаем сетевые интерфейсы из данных SNMP
 * @param {Object} vuln
 * @returns {*}
 */
function getSNMPNetworkInterfaces(vuln) {
  const ID_KEY = 1;
  const MAC_KEY = 6;

  const interfaces = formatSingleDimensionParamListTable(vuln.param_list);

  if (interfaces) {
    return interfaces.map((item) => {
      const mac = String(item[MAC_KEY]).match(macAddressRegExp);

      return {
        id: item[ID_KEY],
        mac: mac ? mac[0] : null,
      };
    });
  }

  return undefined;
}

/**
 * Получаем системную информацию из данных SNMP
 * @param {Object} vuln
 * @returns {{ name: String }}
 */
function getSNMPSystemInformation(vuln) {
  const NAME_KEY = 4;

  const info = formatSingleDimensionParamListTable(vuln.param_list, true);

  return { name: info[NAME_KEY] };
}

/**
 * Маппим сетевые интерфейсы с адрессами
 * @param {Array} addresses
 * @param {Array} interfaces
 * @returns {Array}
 */
function formatSNMPInterfaces(addresses, interfaces) {
  const result = [];

  for (const address of addresses) {
    const networkInterface = interfaces.find(item => item.id === address.interfaceId);

    if (networkInterface) {
      delete address.interfaceId;
      address.family = 'ipv4';

      result.push({
        mac: networkInterface.mac,
        address: [address],
      });
    }
  }

  return result;
}


module.exports = {
  parseReferenceLinks,
  getNetworkInterfaceData,
  getNetworkDeviceFirmwareData,
  getWindowsUserData,
  getWindowsSoftwareData,
  getLinuxSoftwareData,
  getNetworkDeviceOrLinuxUserData,
  getNetworkDeviceNetworkAdapterData,
  getSNMPNetworkAddresses,
  getSNMPNetworkInterfaces,
  getSNMPSystemInformation,
  formatSNMPInterfaces,
  getSerialNumbers,
  getDomainName,
};
