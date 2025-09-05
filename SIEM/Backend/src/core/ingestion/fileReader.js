// Backend/src/core/ingestion/fileReader.js

const fs = require('fs');
const fsPromises = require('fs').promises; // For promise-based methods
const path = require('path');
const readline = require('readline');

/**
 * Asynchronously reads all log files in a level's logs directory line by line,
 * skipping empty lines and trimming whitespace. Yields each processed line
 * with the associated filename.
 *
 * @param {string} level - The level name (e.g., 'level1').
 * @yields {Object} { filename: string, line: string } Processed log lines with filename.
 * @throws {Error} If the level is invalid, directory/file is missing, or read errors occur.
 */
async function* readLogFiles(level) {
  if (!level || typeof level !== 'string') {
    throw new Error('Invalid parameter: level must be a non-empty string.');
  }

  const logsDir = path.join(__dirname, '../../../../Data/levels', level, 'logs');

  try {
    // Check if the logs directory exists and is accessible
    await fsPromises.access(logsDir, fs.constants.F_OK | fs.constants.R_OK);
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`Logs directory not found: ${logsDir}`);
    } else if (err.code === 'EACCES') {
      throw new Error(`Permission denied for logs directory: ${logsDir}`);
    } else {
      throw new Error(`Error accessing logs directory: ${err.message}`);
    }
  }

  // Get all .log files in the directory
  const files = (await fsPromises.readdir(logsDir)).filter(file => file.endsWith('.log'));
  console.log(`Found files: ${files.join(', ')}`); // Debug log for file list
  if (files.length === 0) {
    throw new Error(`No .log files found in: ${logsDir}`);
  }

  for (const file of files) {
    const filePath = path.join(logsDir, file);
    console.log(`Processing file: ${filePath}`); // Debug log for current file
    const rl = readline.createInterface({
      input: fs.createReadStream(filePath),
      crlfDelay: Infinity, // Handle all types of line endings
    });

    try {
      for await (let line of rl) {
        line = line.trim();
        if (line) {
          yield { filename: file, line };
        }
      }
      console.log(`Finished processing: ${file}`); // Debug log for completion
    } catch (err) {
      throw new Error(`Error reading log file ${file}: ${err.message}`);
    } finally {
      rl.close();
    }
  }
}

module.exports = { readLogFiles };