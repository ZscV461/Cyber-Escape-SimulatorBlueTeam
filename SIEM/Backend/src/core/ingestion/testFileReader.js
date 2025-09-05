// Backend/src/core/ingestion/testFileReader.js
const path = require('path');
const { parseLogFile } = require('../parser/parser');
const { normalizeLogs } = require('../normalization/normalizer');

async function test() {
  try {
    const basePath = path.join(__dirname, '../../../../Data/levels/level1/logs');
    const files = ['firewall.log', 'windows.log'];

    for (const file of files) {
      const logFilePath = path.join(basePath, file);
      const parsedEvents = await parseLogFile(logFilePath);
      console.log(`Parsed ${parsedEvents.length} events and saved to storage/parsed/${path.basename(file, '.log')}.json`);
    }

    const firewallResult = await normalizeLogs('firewall');
    console.log(`Normalization complete for firewall: Total ${firewallResult.total}, Success ${firewallResult.success}, Warnings ${firewallResult.warnings}`);

    const windowsResult = await normalizeLogs('windows');
    console.log(`Normalization complete for windows: Total ${windowsResult.total}, Success ${windowsResult.success}, Warnings ${windowsResult.warnings}`);
  } catch (err) {
    console.error('Test failed:', err.message);
  }
}

test();