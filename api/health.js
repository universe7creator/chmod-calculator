export default function handler(req, res) {
  res.json({
    status: 'healthy',
    service: 'chmod-calculator',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
}
