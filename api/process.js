export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { numeric, symbolic, permissions } = req.body;
    
    let result = {
      numeric: null,
      symbolic: null,
      owner: { read: false, write: false, execute: false },
      group: { read: false, write: false, execute: false },
      other: { read: false, write: false, execute: false },
      special: { setuid: false, setgid: false, sticky: false }
    };

    if (numeric) {
      const mode = parseInt(numeric, 8);
      result.special.setuid = !!(mode & 0o4000);
      result.special.setgid = !!(mode & 0o2000);
      result.special.sticky = !!(mode & 0o1000);
      result.owner.read = !!(mode & 0o400);
      result.owner.write = !!(mode & 0o200);
      result.owner.execute = !!(mode & 0o100);
      result.group.read = !!(mode & 0o040);
      result.group.write = !!(mode & 0o020);
      result.group.execute = !!(mode & 0o010);
      result.other.read = !!(mode & 0o004);
      result.other.write = !!(mode & 0o002);
      result.other.execute = !!(mode & 0o001);
    }

    res.json({ success: true, result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}
