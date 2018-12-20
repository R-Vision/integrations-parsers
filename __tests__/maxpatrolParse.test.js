/* eslint-disable import/no-extraneous-dependencies */

'use strict';

const path = require('path');
const fs = require('fs');
const unzip = require('unzip-stream');

const maxPatrolParse = require('../maxpatrol-parse');


const parseOptions = {
  include_software: true,
  include_users: true,
};

function cb(err, result) {
  expect(result).toMatchSnapshot();
}

async function testReport(filename) {
  // архив должен иметь определенный алгоритм сжатия, подходят не все
  // например можно пользоваться https://www.files2zip.com/
  const zipPath = path.join(__dirname, 'testData.zip');
  const fullFilename = `${filename}.xml`;

  fs.createReadStream(zipPath)
    .pipe(unzip.Parse())
    .on('entry', (entry) => {
      if (entry.path === fullFilename) {
        maxPatrolParse(entry, parseOptions, cb);
      } else {
        entry.autodrain();
      }
    });

  // ждем - парсинг иногда занимает время
  await new Promise(resolve => setTimeout(resolve, 2000));
}

describe('parse', () => {
  test('Windows host data matches snapshot', async () => {
    await testReport('windows');
  }, 10000);

  test('Linux host data matches snapshot', async () => {
    await testReport('linux');
  }, 10000);

  test('Cisco host data matches snapshot', async () => {
    await testReport('cisco');
  }, 10000);

  test('HP host data matches snapshot', async () => {
    await testReport('hp');
  }, 10000);

  test('Juniper host data matches snapshot', async () => {
    await testReport('juniper');
  }, 10000);

  test('error handling data matches snapshot', async () => {
    await testReport('invalid_linux');
  }, 10000);
});
