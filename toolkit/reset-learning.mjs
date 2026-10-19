// Wipe the self-improvement knowledge store (keeps one .bak for undo).
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { resetKnowledge } from './lib/memory.mjs';

const KPATH = join(dirname(fileURLToPath(import.meta.url)), '.memory', 'knowledge.json');
resetKnowledge(KPATH);
console.log(`learning reset. Store cleared: ${KPATH} (a .bak was kept if one existed).`);
