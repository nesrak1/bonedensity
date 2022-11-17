![logo](logo.png)

See writeup which started this: https://nesrak1.github.io/2022/11/13/flareon09-11.html

1. If the program is a pyinstaller exe, use pyinstxtractor to extract it.
2. Install the correct version of Python (pyinstxtractor will tell you which, if you used that)
3. Install pycryptodome for that version of Python
4. Run either of these commands

```
python bd.py encrypted_file.pyc _pytransform.dll
python bd.py encrypted_file.pyc pytransform.pyd
```

Use the pytransform.pyd file if you have it,
otherwise, use the _pytransform.dll version.

5. Pycdc will attempt to decompile. It's not very good (especially since it doesn't really support new versions of Python), so you may want to use pycdas instead on the `.pyc.fix.pyc` file. You can try uncompyle6/decompyle3 but so far in testing, none of them have decompiled with those two.

Note: only windows dlls/pyds are supported right now.

If you're on Linux, you'll need to compile tomcrypt_ctr (normal mode only).
This is temporary measure since pycryptodome wasn't working.
The source for tomcrypt_ctr is in tomcrypt_ctr.c (obviously).

Libraries:

* Pycdc: https://github.com/zrax/pycdc
* tomcrypt: https://github.com/libtom/libtomcrypt

Some extra code from:

* unpyarmor: https://github.com/nlscc/unpyarmor