import { Worker } from 'bullmq';
import { createQueue } from './lib/queue';
import { startScanWorker } from './lib/engine';

const queue = createQueue();

const worker = new Worker('scan:queue', async (job) => {
  console.log(`Processing job ${job.id}: ${job.data.target}`);
  await startScanWorker(job.data);
}, {
  connection: {
    host: process.env.REDIS_URL
  }
});

worker.on('completed', (job) => {
  console.log(`Job ${job.id} completed`);
});

worker.on('failed', (job, err) => {
  console.error(`Job ${job.id} failed:`, err);
});

console.log('Worker started and listening to scan:queue');