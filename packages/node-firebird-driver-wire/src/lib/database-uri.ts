export interface ParsedDatabaseUri {
  readonly host: string;
  readonly port: number;
  readonly database: string;
}

export function parseDatabaseUri(uri: string): ParsedDatabaseUri {
  // Treat rooted Windows drive paths as hostless URIs.
  if (/^[A-Za-z]:(?:[\\/]|$)/.test(uri)) {
    return {
      host: 'localhost',
      port: 3050,
      database: uri,
    };
  }

  const match = /^(?:(.+?)(?:\/(\d+))?:)?(.+)$/.exec(uri);
  if (!match) {
    throw new Error(`Invalid Firebird database URI '${uri}'.`);
  }

  return {
    host: match[1] || 'localhost',
    port: match[2] ? parseInt(match[2], 10) : 3050,
    database: match[3],
  };
}
