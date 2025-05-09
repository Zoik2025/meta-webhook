import crypto from 'crypto';
import axios from 'axios';

const APP_SECRET = process.env.META_APP_SECRET;
const MAKE_WEBHOOK_URL = process.env.MAKE_WEBHOOK_URL;

export default async function handler(req, res) {
  if (req.method === 'GET') {
    const VERIFY_TOKEN = process.env.META_VERIFY_TOKEN;
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode && token === VERIFY_TOKEN) {
      return res.status(200).send(challenge);
    } else {
      return res.status(403).send('Error de verificación');
    }
  }

  if (req.method === 'POST') {
    const signature = req.headers['x-hub-signature-256'];
    const expectedHash = 'sha256=' + crypto
      .createHmac('sha256', APP_SECRET)
      .update(JSON.stringify(req.body))
      .digest('hex');

    if (signature !== expectedHash) {
      return res.status(403).send('Firma inválida');
    }

    await axios.post(MAKE_WEBHOOK_URL, req.body);
    return res.status(200).send('Recibido y reenviado');
  }

  return res.status(405).send('Método no permitido');
}