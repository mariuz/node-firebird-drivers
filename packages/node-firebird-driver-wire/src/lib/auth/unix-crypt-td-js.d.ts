declare module 'unix-crypt-td-js' {
  function unixCryptTD(
    password: string | readonly number[],
    salt: string | readonly number[],
    returnBytes?: false,
  ): string;

  function unixCryptTD(
    password: string | readonly number[],
    salt: string | readonly number[],
    returnBytes: true,
  ): number[];

  export = unixCryptTD;
}
