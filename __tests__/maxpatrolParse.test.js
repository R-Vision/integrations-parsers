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

  describe('parse affected software', () => {
    it('silverlight', async () => {
      const result = await parseReport('windows');

      const silverlightVulns = result.hosts[0].affectedSoftware.find(soft => soft.name === 'Microsoft Silverlight');
      expect(silverlightVulns).toEqual({
        installPath:
          'C:\\Program Files (x86)\\Microsoft Silverlight\\sllauncher.exe',
        name: 'Microsoft Silverlight',
        version: '5.1.50428.0',
        vulnsUids: ['414284', '414339', '414475', '414565', '414677', '414767'],
      });
    }, 10000);

    it('all properties must be defined', async () => {
      const result = await parseReport('windows');

      for (const affectedSoftware of result.hosts[0].affectedSoftware) {
        expect(affectedSoftware).toHaveProperty('installPath');
        expect(typeof affectedSoftware.name).toBe('string');
        expect(typeof affectedSoftware.version).toBe('string');
        expect(Array.isArray(affectedSoftware.vulnsUids)).toBeTruthy();
      }
    }, 10000);
  });
});
