# vimdecrypt

Tool for decrypting VIM encrypted files.

Install:
```shell
go install github.com/doggeddog/vimdecrypt/vimdecrpyt
```

Usage:
```shell
vimdecrypt -p ${password} ${filename}
```

Only support `Blowfish2 / bf2` encrypt method.
```shell
command: set cryptmethod=blowfish2
header: VimCrypt~03!
```

Thanks
================

* [vimdecrypt](https://github.com/nlitsme/vimdecrypt) by Willem Hengeveld