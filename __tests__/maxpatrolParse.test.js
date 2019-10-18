const path = require('path');
const fs = require('fs');

const maxPatrolParse = require('../maxpatrol-parse');

const parseOptions = {
  include_software: true,
  include_users: true,
  filter_vulnerabilities_paths: [
    /C:\\Program Files \(x86\)\\Microsoft Silverlight\\sllauncher\.exe/i,
  ],
};

function parseReport(filename) {
  return new Promise((resolve, reject) => {
    const testFilePath = path.join(__dirname, 'testData', `${filename}.xml`);
    const testDataStream = fs.createReadStream(testFilePath);

    maxPatrolParse(testDataStream, parseOptions, (err, result) => {
      if (err) {
        reject(err);
      } else {
        resolve(result);
      }
    });
  });
}

describe('parse', () => {
  it('Windows host data matches snapshot', async () => {
    const result = await parseReport('windows');
    expect(result).toMatchSnapshot();
  }, 10000);

  it('Linux host data matches snapshot', async () => {
    const result = await parseReport('linux');
    expect(result).toMatchSnapshot();
  }, 10000);

  it('Cisco host data matches snapshot', async () => {
    const result = await parseReport('cisco');
    expect(result).toMatchSnapshot();
  }, 10000);

  it('Cisco ASA host data matches snapshot', async () => {
    const result = await parseReport('cisco-asa');
    expect(result).toMatchSnapshot();
  }, 10000);

  it('HP host data matches snapshot', async () => {
    const result = await parseReport('hp');
    expect(result).toMatchSnapshot();
  }, 10000);

  it('Juniper host data matches snapshot', async () => {
    const result = await parseReport('juniper');
    expect(result).toMatchSnapshot();
  }, 10000);

  it('error handling data matches snapshot', async () => {
    const result = await parseReport('invalid_linux');
    expect(result).toMatchSnapshot();
  }, 10000);

  it('invalid format report matches snapshot', async () => {
    const result = await parseReport('audit_only_report');
    expect(result).toMatchSnapshot();
  }, 10000);
});
