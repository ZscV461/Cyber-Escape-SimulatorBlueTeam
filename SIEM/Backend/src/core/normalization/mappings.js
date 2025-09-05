module.exports = {
  firewall: {
    transform: (entry) => {
      const protocolMatch = entry.raw.match(/\b(TCP|UDP|ICMP)\b/i);
      const sourceMatch = entry.raw.match(/(\d+\.\d+\.\d+\.\d+)(?::(\d+))?/);
      const destMatch = entry.raw.match(/->\s*(\d+\.\d+\.\d+\.\d+)(?::(\d+))?/);
      const actionMatch = entry.raw.match(/\b(ALLOW|DENY)\b/i);

      return {
        'log.original': entry.raw,
        '@timestamp': new Date(entry['@timestamp']).toISOString(),
        'observer.type': 'host',
        'event.category': 'network',
        'event.type': 'network_traffic',
        'event.action': actionMatch ? actionMatch[0].toLowerCase() : null,
        'network.protocol': protocolMatch ? protocolMatch[0].toUpperCase() : null,
        'source.ip': sourceMatch ? sourceMatch[1] : null,
        'source.port': sourceMatch && sourceMatch[2] ? parseInt(sourceMatch[2], 10) : null,
        'destination.ip': destMatch ? destMatch[1] : null,
        'destination.port': destMatch && destMatch[2] ? parseInt(destMatch[2], 10) : null
      };
    }
  },

  windows: {
    transform: (entry) => {
      const userMatch = entry.raw.match(/User\s+"([^"]+)"|for\s+user\s+"([^"]+)"/i);
      const ipMatch = entry.raw.match(/from\s+(\d+\.\d+\.\d+\.\d+)/i);
      let action = null;
      let outcome = null;

      if (/logged in/i.test(entry.raw)) {
        action = 'login';
        outcome = 'success';
      } else if (/Failed login attempt/i.test(entry.raw)) {
        action = 'login';
        outcome = 'failure';
      } else if (/Password change attempt/i.test(entry.raw)) {
        action = 'password_change';
        outcome = 'warning';
      }

      return {
        'log.original': entry.raw,
        '@timestamp': new Date(entry['@timestamp']).toISOString(),
        'observer.type': 'host',
        'event.category': 'authentication',
        'event.type': 'security',
        'event.action': action,
        'event.outcome': outcome,
        'user.name': userMatch ? (userMatch[1] || userMatch[2]) : null,
        'source.ip': ipMatch ? ipMatch[1] : null
      };
    }
  }
};
