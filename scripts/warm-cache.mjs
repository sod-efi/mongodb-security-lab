/*
 * Build-time helper for the Docker image: boots one in-memory mongod so
 * mongodb-memory-server downloads its binary into the image layer. The
 * first real run is then instant — and works with no network at all.
 */
import { MongoMemoryServer } from 'mongodb-memory-server-core';

const srv = await MongoMemoryServer.create();
console.log('mongod binary cached:', srv.getUri());
await srv.stop();
console.log('warm-cache done');
