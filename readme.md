![logo](logo.png)

See writeup which started this: https://nesrak1.github.io/2022/11/13/flareon09-11.html

```
python bd.py encrypted_file.pyc _pytransform.dll
python bd.py encrypted_file.pyc pytransform.pyc
```

Use the pytransform.pyc file if you have it,
otherwise, use the _pytransform.dll version.

Note: only windows dlls/pycs are supported right now.

If you're on Linux, you'll need to compile tomcrypt_ctr (normal mode only).
This is temporary measure since pycryptodome wasn't working.
The source for tomcrypt_ctr is in tomcrypt_ctr.c (obviously).

Libraries:

* Pycdc: https://github.com/zrax/pycdc
* tomcrypt: https://github.com/libtom/libtomcrypt

Some extra code from:

* unpyarmor: https://github.com/nlscc/unpyarmor