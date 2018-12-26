'use strict';

const path = require('path');
const fs = require('fs');

const maxPatrolParse = require('../maxpatrol-parse');


const parseOptions = {
  include_software: true,
  include_users: true,
};

function cb(err, result) {
  expect(result).toMatchSnapshot();
}

async function testReport(filename) {
  const testFilePath = path.join(__dirname, 'testData', `${filename}.xml`);
  const testDataStream = fs.createReadStream(testFilePath);

  maxPatrolParse(testDataStream, parseOptions, cb);

  // ждем - парсинг иногда занимает время
  await new Promise(resolve => setTimeout(resolve, 3000));
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

  test('Cisco ASA host data matches snapshot', async () => {
    await testReport('cisco-asa');
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
