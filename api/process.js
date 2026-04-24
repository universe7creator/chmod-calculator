export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { numeric, symbolic, permissions, calculateUmask, comparePermissions } = req.body;

    // Numeric to full conversion
    if (numeric !== undefined) {
      const mode = parseInt(numeric, 8);
      const result = parseNumericMode(mode);
      return res.json({ success: true, result });
    }

    // Symbolic to numeric conversion
    if (symbolic) {
      const result = parseSymbolicMode(symbolic);
      return res.json({ success: true, result });
    }

    // Permission object to both formats
    if (permissions) {
      const numeric = permissionsToNumeric(permissions);
      const sym = permissionsToSymbolic(permissions);
      return res.json({
        success: true,
        result: {
          numeric: numeric.toString().padStart(3, '0'),
          symbolic: sym,
          permissions: permissions
        }
      });
    }

    // Umask calculation
    if (calculateUmask) {
      const umask = parseInt(calculateUmask, 8);
      const fileMode = 0o666 & ~umask;
      const dirMode = 0o777 & ~umask;
      return res.json({
        success: true,
        result: {
          umask: calculateUmask.toString().padStart(3, '0'),
          defaultFileMode: fileMode.toString(8).padStart(3, '0'),
          defaultDirMode: dirMode.toString(8).padStart(3, '0'),
          defaultFileSymbolic: modeToSymbolic(fileMode),
          defaultDirSymbolic: modeToSymbolic(dirMode)
        }
      });
    }

    // Compare permissions
    if (comparePermissions && Array.isArray(comparePermissions)) {
      const comparison = comparePermissions.map(mode => {
        const parsed = typeof mode === 'string' && mode.match(/^[0-7]{3,4}$/)
          ? parseNumericMode(parseInt(mode, 8))
          : parseSymbolicMode(mode);
        return { input: mode, ...parsed };
      });
      return res.json({ success: true, result: { comparison } });
    }

    // Default: return current state
    return res.json({
      success: true,
      message: 'Chmod Calculator API - Use numeric, symbolic, permissions, calculateUmask, or comparePermissions'
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

function parseNumericMode(mode) {
  return {
    numeric: mode.toString(8).padStart(mode >= 0o1000 ? 4 : 3, '0'),
    symbolic: modeToSymbolic(mode),
    owner: {
      read: !!(mode & 0o400),
      write: !!(mode & 0o200),
      execute: !!(mode & 0o100)
    },
    group: {
      read: !!(mode & 0o040),
      write: !!(mode & 0o020),
      execute: !!(mode & 0o010)
    },
    other: {
      read: !!(mode & 0o004),
      write: !!(mode & 0o002),
      execute: !!(mode & 0o001)
    },
    special: {
      setuid: !!(mode & 0o4000),
      setgid: !!(mode & 0o2000),
      sticky: !!(mode & 0o1000)
    }
  };
}

function parseSymbolicMode(sym) {
  // Parse symbolic notation like "rwxr-xr-x" or "rw-r--r--"
  const clean = sym.replace(/\s/g, '').toLowerCase();

  // Validate format
  if (!clean.match(/^[rwxst-]{9}$/)) {
    throw new Error('Invalid symbolic notation. Expected format: rwxr-xr-x');
  }

  const parts = [
    clean.substring(0, 3),  // owner
    clean.substring(3, 6),  // group
    clean.substring(6, 9)   // other
  ];

  let mode = 0;
  const permissions = {
    owner: { read: false, write: false, execute: false },
    group: { read: false, write: false, execute: false },
    other: { read: false, write: false, execute: false },
    special: { setuid: false, setgid: false, sticky: false }
  };

  parts.forEach((part, idx) => {
    const offset = [0o400, 0o040, 0o004][idx];
    if (part[0] === 'r') { mode += offset; permissions[['owner', 'group', 'other'][idx]].read = true; }
    if (part[1] === 'w') { mode += offset >> 1; permissions[['owner', 'group', 'other'][idx]].write = true; }
    if (part[2] === 'x' || part[2] === 's' || part[2] === 't') {
      mode += offset >> 2;
      permissions[['owner', 'group', 'other'][idx]].execute = true;
    }
    if (part[2] === 's' && idx === 0) { mode += 0o4000; permissions.special.setuid = true; }
    if (part[2] === 's' && idx === 1) { mode += 0o2000; permissions.special.setgid = true; }
    if (part[2] === 't' && idx === 2) { mode += 0o1000; permissions.special.sticky = true; }
  });

  return {
    numeric: mode.toString(8).padStart(mode >= 0o1000 ? 4 : 3, '0'),
    symbolic: clean,
    ...permissions
  };
}

function modeToSymbolic(mode) {
  const owner = [
    mode & 0o400 ? 'r' : '-',
    mode & 0o200 ? 'w' : '-',
    mode & 0o100 ? (mode & 0o4000 ? 's' : 'x') : (mode & 0o4000 ? 'S' : '-')
  ].join('');

  const group = [
    mode & 0o040 ? 'r' : '-',
    mode & 0o020 ? 'w' : '-',
    mode & 0o010 ? (mode & 0o2000 ? 's' : 'x') : (mode & 0o2000 ? 'S' : '-')
  ].join('');

  const other = [
    mode & 0o004 ? 'r' : '-',
    mode & 0o002 ? 'w' : '-',
    mode & 0o001 ? (mode & 0o1000 ? 't' : 'x') : (mode & 0o1000 ? 'T' : '-')
  ].join('');

  return owner + group + other;
}

function permissionsToNumeric(perm) {
  let mode = 0;
  if (perm.owner?.read) mode += 0o400;
  if (perm.owner?.write) mode += 0o200;
  if (perm.owner?.execute) mode += 0o100;
  if (perm.group?.read) mode += 0o040;
  if (perm.group?.write) mode += 0o020;
  if (perm.group?.execute) mode += 0o010;
  if (perm.other?.read) mode += 0o004;
  if (perm.other?.write) mode += 0o002;
  if (perm.other?.execute) mode += 0o001;
  if (perm.special?.setuid) mode += 0o4000;
  if (perm.special?.setgid) mode += 0o2000;
  if (perm.special?.sticky) mode += 0o1000;
  return mode;
}

function permissionsToSymbolic(perm) {
  const owner = [
    perm.owner?.read ? 'r' : '-',
    perm.owner?.write ? 'w' : '-',
    perm.owner?.execute ? (perm.special?.setuid ? 's' : 'x') : (perm.special?.setuid ? 'S' : '-')
  ].join('');

  const group = [
    perm.group?.read ? 'r' : '-',
    perm.group?.write ? 'w' : '-',
    perm.group?.execute ? (perm.special?.setgid ? 's' : 'x') : (perm.special?.setgid ? 'S' : '-')
  ].join('');

  const other = [
    perm.other?.read ? 'r' : '-',
    perm.other?.write ? 'w' : '-',
    perm.other?.execute ? (perm.special?.sticky ? 't' : 'x') : (perm.special?.sticky ? 'T' : '-')
  ].join('');

  return owner + group + other;
}
