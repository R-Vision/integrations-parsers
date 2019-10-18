const fs = require('fs');
const path = require('path');

const nessusParse = require('../nessus-parse');

/**
 * @param {string} csvFile
 */
const parseCsvReport = csvFile =>
  new Promise((resolve, reject) => {
    const stream = fs.createReadStream(
      path.join(__dirname, 'testData', csvFile),
    );

    nessusParse(stream, (err, results) => {
      if (err) {
        reject(err);
      } else {
        resolve(results);
      }
    });
  });

describe('nessus', () => {
  it('parse nessus.csv', async () => {
    const result = await parseCsvReport('nessus.csv');
    expect(result).toMatchSnapshot();
  }, 30000);

  it('parse web_sites_5bedu7.csv', async () => {
    const result = await parseCsvReport('web_sites_5bedu7.csv');
    expect(result).toMatchSnapshot();
  }, 30000);

  it('parse R-Vision_network_vfk66r.csv', async () => {
    const result = await parseCsvReport('R-Vision_network_vfk66r.csv');
    expect(result).toMatchSnapshot();
  }, 30000);
});
