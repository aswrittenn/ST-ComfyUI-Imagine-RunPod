import { createHash, createHmac } from 'node:crypto';

export const info = {
    id: 'comfy-imagine-runpod-s3',
    name: 'Comfy Imagine RunPod S3 LoRA browser',
    description: 'Lists LoRA filenames from a RunPod network volume for the Comfy Imagine UI extension.',
};

const sha256 = value => createHash('sha256').update(value).digest('hex');
const hmac = (key, value, encoding) => createHmac('sha256', key).update(value).digest(encoding);
const awsEncode = value => encodeURIComponent(value).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

function decodeXml(value) {
    return value.replace(/&(#x[\da-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (_, entity) => {
        if (entity[0] === '#') {
            const hex = entity[1]?.toLowerCase() === 'x';
            const code = Number.parseInt(entity.slice(hex ? 2 : 1), hex ? 16 : 10);
            try {
                return Number.isInteger(code) && code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : _;
            } catch {
                return _;
            }
        }
        return ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" })[entity.toLowerCase()] ?? _;
    });
}

function signListRequest({ host, bucket, datacenter, accessKey, secretKey, prefix, continuationToken }) {
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const date = amzDate.slice(0, 8);
    const query = { 'list-type': '2', prefix };
    if (continuationToken) query['continuation-token'] = continuationToken;
    const canonicalQuery = Object.entries(query)
        .map(([key, value]) => [awsEncode(key), awsEncode(value)])
        .sort(([ak, av], [bk, bv]) => ak.localeCompare(bk) || av.localeCompare(bv))
        .map(([key, value]) => `${key}=${value}`).join('&');
    const canonicalUri = `/${awsEncode(bucket)}`;
    const payloadHash = sha256('');
    const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
    const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
    const canonicalRequest = ['GET', canonicalUri, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join('\n');
    const scope = `${date}/${datacenter}/s3/aws4_request`;
    const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonicalRequest)].join('\n');
    const dateKey = hmac(`AWS4${secretKey}`, date);
    const regionKey = hmac(dateKey, datacenter);
    const serviceKey = hmac(regionKey, 's3');
    const signingKey = hmac(serviceKey, 'aws4_request');
    const signature = hmac(signingKey, stringToSign, 'hex');
    return {
        url: `https://${host}${canonicalUri}?${canonicalQuery}`,
        headers: {
            'x-amz-content-sha256': payloadHash,
            'x-amz-date': amzDate,
            Authorization: `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
        },
    };
}

export async function init(router) {
    router.post('/loras', async (request, response) => {
        try {
            const { volumeId, datacenter, accessKey, secretKey } = request.body ?? {};
            if (typeof volumeId !== 'string' || !/^[a-zA-Z0-9-]+$/.test(volumeId)) {
                return response.status(400).json({ error: 'Enter a valid RunPod network volume ID.' });
            }
            if (typeof datacenter !== 'string' || !/^[a-zA-Z0-9-]+$/.test(datacenter)) {
                return response.status(400).json({ error: 'Enter the volume data-center ID, for example EU-SE-1.' });
            }
            if (typeof accessKey !== 'string' || !accessKey.trim() || typeof secretKey !== 'string' || !secretKey.trim()) {
                return response.status(400).json({ error: 'Enter your RunPod S3 access key and secret key.' });
            }

            const dc = datacenter.toLowerCase();
            const host = `s3api-${dc}.runpod.io`;
            const prefix = 'models/loras/';
            const loras = [];
            let continuationToken;
            // Bound pagination so an unusually large volume cannot hold a request open indefinitely.
            for (let page = 0; page < 20; page++) {
                const signed = signListRequest({
                    host, bucket: volumeId, datacenter, accessKey: accessKey.trim(),
                    secretKey: secretKey.trim(), prefix, continuationToken,
                });
                const result = await fetch(signed.url, { headers: signed.headers, redirect: 'error' });
                const xml = await result.text();
                if (!result.ok) {
                    console.warn(`RunPod S3 LoRA listing failed: HTTP ${result.status}`);
                    return response.status(502).json({ error: `RunPod S3 API returned HTTP ${result.status}. Check the S3 keys, volume ID, data center, and S3 API availability there.` });
                }
                const keys = [...xml.matchAll(/<Key>([\s\S]*?)<\/Key>/g)].map(match => decodeXml(match[1]));
                for (const key of keys) {
                    if (!key.startsWith(prefix) || !key.toLowerCase().endsWith('.safetensors')) continue;
                    const name = key.slice(prefix.length);
                    if (name && !name.split('/').some(part => part === '..')) loras.push(name);
                }
                const truncated = /<IsTruncated>true<\/IsTruncated>/i.test(xml);
                if (!truncated) break;
                const tokenMatch = xml.match(/<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/);
                if (!tokenMatch) break;
                continuationToken = decodeXml(tokenMatch[1]);
            }
            return response.json({ loras: [...new Set(loras)].sort((a, b) => a.localeCompare(b)) });
        } catch (error) {
            console.error('RunPod S3 LoRA listing error:', error.message);
            return response.status(502).json({ error: error.message || 'Could not reach RunPod S3 API.' });
        }
    });
}
