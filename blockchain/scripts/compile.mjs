import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import solc from 'solc';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = fs.readFileSync(path.join(root, 'contracts/EvidenceRegistry.sol'), 'utf8');
const input = {
  language: 'Solidity',
  sources: {'EvidenceRegistry.sol': {content: source}},
  settings: {
    optimizer: {enabled: true, runs: 200}, evmVersion: 'paris',
    outputSelection: {'*': {'*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object', 'evm.methodIdentifiers']}}
  }
};
const output = JSON.parse(solc.compile(JSON.stringify(input)));
for (const error of output.errors || []) {
  console.error(error.formattedMessage);
  if (error.severity === 'error') process.exitCode = 1;
}
if (process.exitCode) process.exit(process.exitCode);
const contract = output.contracts['EvidenceRegistry.sol'].EvidenceRegistry;
const artifact = {compiler: solc.version(), source: 'EvidenceRegistry.sol', evmVersion: 'paris',
  abi: contract.abi, bytecode: '0x' + contract.evm.bytecode.object,
  deployedBytecode: '0x' + contract.evm.deployedBytecode.object,
  methods: contract.evm.methodIdentifiers};
fs.writeFileSync(path.join(root, '../securefi/EvidenceRegistry.json'), JSON.stringify(artifact, null, 2) + '\n');
console.log('Compiled EvidenceRegistry into securefi/EvidenceRegistry.json');
