# Nighthawk DLL Configuration Extractor

The provided configuration extractor is written in Python and works statically on some variants of the Nighthawk DLL. This extractor is currently active in [CAPEv2](https://github.com/kevoreilly/CAPEv2/blob/master/modules/processing/parsers/CAPE/Nighthawk.py).

### Configuration Extractor

The standalone script is available [here](./assets/scripts/nighthawk_config_extract.py).

### Usage

```bash
$ python3 nighthawk_config_extract.py --help
usage: Nighthawk DLL Configuration Extractor [-h] --fpath FPATH

options:
  -h, --help            show this help message and exit
  --fpath FPATH, -f FPATH
                        Path to Nighthawk DLL
```

### Examples

* 0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988 ([Malware Bazaar](https://bazaar.abuse.ch/sample/0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988))

```bash
$ python3 nighthawk_config_extract.py -f 0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988
{'Ciphertext Alphabet': b'JCljOF5fN?TZLyuBt6x-[nYe,E42U.)wD+Qh$zIGVK_]rm9A}{d('
                        b'c3^=>17g!P&SMW:Xsk iq;Rop/v0<a8Hb*\x00',
 'Config AES-128 CBC Decryption Key': b'8CVKEWJUVHSW4CBC',
 'Implant Config': {'implant-config': {'general-config': {'code-modules': {'egress-transports': [],
                                                                           'encoders': [],
                                                                           'p2p-transports': []},
                                                          'injector': {'methods': {'AllocMemory': 'VirtualAllocNative',
                                                                                   'ExecuteMemory': 'CreateThreadNative',
                                                                                   'ProcessCreate': 'CreateProcessWinApi',
                                                                                   'ProcessOpen': 'OpenProcessNative',
                                                                                   'ProtectMemory': 'VirtualProtectNative',
                                                                                   'WriteMemory': 'WriteProcMemNative'},
                                                                       'parent-process': 'C:\\windows\\explorer.exe',
                                                                       'spawn-to': 'C:\\windows\\system32\\browser_broker.exe'},
                                                          'opsec': {'--backing-module': {'x64': 'chakra.dll',
                                                                                         'x86': 'chakra.dll'},
                                                                    'clear-dll-notifications': True,
                                                                    'clear-hwbp-on-imp-res': True,
                                                                    'clear-hwbp-on-unhook': True,
                                                                    'clear-veh-on-imp-res': True,
                                                                    'clear-veh-on-unhook': True,
                                                                    'disable-pi-callback': True,
                                                                    'encrypt-heap-mode': 'implant',
                                                                    'hide-windows': False,
                                                                    'indirect-syscalls': True,
                                                                    'loader-export': 'ReadFile',
                                                                    'masquerade-thread-stacks': True,
                                                                    'ordinary-export': '',
                                                                    'report-self-encrypt-status': True,
                                                                    'self-encrypt': True,
                                                                    'self-encrypt-after': 5000,
                                                                    'self-encrypt-no-rx-stub': True,
                                                                    'self-encrypt-while-listening': True,
                                                                    'stack-commit-size': 262144,
                                                                    'stomp-pe-header': True,
                                                                    'thread-start-addresses': ['ntdll!RtlUserThreadStart'],
                                                                    'unhook-dlls': ['kernel32.dll',
                                                                                    'ntdll.dll',
                                                                                    'kernelbase.dll',
                                                                                    'winhttp.dll'],
                                                                    'unhook-on-self-encrypt': True,
                                                                    'unhook-syscalls': True,
                                                                    'unhook-using-wpm': True,
                                                                    'use-syscalls': True},
                                                          'settings': {'expire-after': 1640998861,
                                                                       'interval': 10000,
                                                                       'jitter': 40}},
                                       'mode': 'p2p',
                                       'p2p-config': {'aes-128-iv': 'Vnzix2bnX2cpeCw4',
                                                      'aes-128-key': 'TZNZ4PdCXeu3Aq7i',
                                                      'p2p-listener-uri': ['smb://googlecrashpad'],
                                                      'promote': False,
                                                      'promote-after': 1}}},
 'Plaintext Alphabet': b'K:sPZv2oAH,MkB_Ow)?pa$ b{F0V-YC4<uUJ^TQG6+ytz;=iqL9I'
                       b'W.ng/S7X1R(rxc5]elD[*8hfE>3m&Nj!d}\x00'}
```

* 9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8 ([Malware Bazaar](https://bazaar.abuse.ch/sample/9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8))

```bash
$ python3 nighthawk_config_extract.py -f 9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8
{'Ciphertext Alphabet': b'cezH!g27E>-?pnkI5ym6QG<wXr;ORhZDKY._:^u{UWt,j[9vasb*'
                        b'l/CBxF=q0d fo&4)N]M}3ST(J$8PiA+LV1\x00',
 'Config AES-128 CBC Decryption Key': b'DLVXARU0R88AM0HF',
 'Implant Config': {'implant-config': {'egress-config': {'aes-128-iv': '6d772CikeWzQ0Ah3',
                                                         'aes-128-key': 'CpblR6YW5b3OQwZW',
                                                         'c2-fallback-uri': '',
                                                         'c2-uri': 'https://trulieveapp.azurewebsites.net;https://trulievetesting.azurewebsites.net',
                                                         'commands': {'getcommand': {'build-request': {'headers': {'Accept': '*/*',
                                                                                                                   'Connection': 'close',
                                                                                                                   'User-Agent': 'Mozilla/5.0 '
                                                                                                                                 '(Windows '
                                                                                                                                 'NT '
                                                                                                                                 '6.1; '
                                                                                                                                 'WOW64; '
                                                                                                                                 'Trident/7.0; '
                                                                                                                                 'rv:11.0) '
                                                                                                                                 'like '
                                                                                                                                 'Gecko',
                                                                                                                   'X-ASPNET-VERSION': '1.5'},
                                                                                                       'method': 'get',
                                                                                                       'path': '/ping?f=<metadata:BuiltIn.Text.Base64UrlEncode>'},
                                                                                     'response-success': {'body': '^(?P<payload:BuiltIn.Text.Base64UrlDecode>[^]+)$',
                                                                                                          'status': 200}},
                                                                      'listcommands': {'build-request': {'headers': {'Accept': '*/*',
                                                                                                                     'Connection': 'close',
                                                                                                                     'User-Agent': 'Mozilla/5.0 '
                                                                                                                                   '(Windows '
                                                                                                                                   'NT '
                                                                                                                                   '6.1; '
                                                                                                                                   'WOW64; '
                                                                                                                                   'Trident/7.0; '
                                                                                                                                   'rv:11.0) '
                                                                                                                                   'like '
                                                                                                                                   'Gecko',
                                                                                                                     'X-ASPNET-VERSION': '1.5'},
                                                                                                         'method': 'get',
                                                                                                         'path': '/ping?f=<metadata:BuiltIn.Text.Base64UrlEncode>'},
                                                                                       'response-success': {'headers': {'Set-Cookie': '^[^]*?csrftoken=(?P<payload:BuiltIn.Text.Base64UrlDecode>[^;]+)[^]*$'},
                                                                                                            'status': 200}},
                                                                      'putresult': {'build-request': {'body': 'session=<payload:BuiltIn.Text.Base64UrlEncode>',
                                                                                                      'headers': {'Accept': '*/*',
                                                                                                                  'Connection': 'close',
                                                                                                                  'Cookie': '_ga=<metadata:BuiltIn.Text.Base64UrlEncode>',
                                                                                                                  'User-Agent': 'Mozilla/5.0 '
                                                                                                                                '(Windows '
                                                                                                                                'NT '
                                                                                                                                '6.1; '
                                                                                                                                'WOW64; '
                                                                                                                                'Trident/7.0; '
                                                                                                                                'rv:11.0) '
                                                                                                                                'like '
                                                                                                                                'Gecko',
                                                                                                                  'X-ASPNET-VERSION': '1.5'},
                                                                                                      'method': 'post',
                                                                                                      'path': '^/api/v1/station/playbackResumed'},
                                                                                    'response-success': {'status': 200}},
                                                                      'status': {'build-request': {'headers': {'Accept': '*/*',
                                                                                                               'Connection': 'close',
                                                                                                               'User-Agent': 'Mozilla/5.0 '
                                                                                                                             '(Windows '
                                                                                                                             'NT '
                                                                                                                             '6.1; '
                                                                                                                             'WOW64; '
                                                                                                                             'Trident/7.0; '
                                                                                                                             'rv:11.0) '
                                                                                                                             'like '
                                                                                                                             'Gecko',
                                                                                                               'X-ASPNET-VERSION': '1.5'},
                                                                                                   'method': 'get',
                                                                                                   'path': '/ping?f=<metadata:BuiltIn.Text.Base64UrlEncode>'},
                                                                                 'response-success': {'status': 200}}},
                                                         'fallback-p2p': False,
                                                         'retry-attempts-on-error': 99999},
                                       'general-config': {'code-modules': {'egress-transports': [],
                                                                           'encoders': [],
                                                                           'p2p-transports': []},
                                                          'injector': {'methods': {'AllocMemory': 'VirtualAllocNative',
                                                                                   'ExecuteMemory': 'QueueAPCNative',
                                                                                   'ProcessCreate': 'CreateProcessWinApi',
                                                                                   'ProcessOpen': 'OpenProcessNative',
                                                                                   'ProtectMemory': 'VirtualProtectNative',
                                                                                   'ThreadOpen': 'CreateNewThreadNative',
                                                                                   'WriteMemory': 'WriteProcMemNative'},
                                                                       'parent-process': 'explorer.exe',
                                                                       'spawn-to': 'c:\\windows\\system32\\backgroundtaskhost.exe',
                                                                       'use-rwx': False},
                                                          'opsec': {'--backing-module': {'x64': 'chakra.dll',
                                                                                         'x86': 'chakra.dll'},
                                                                    'block-dlls': ['amsi.dll',
                                                                                   'CrowdStrike.Sensor.ScriptControl14505.dll',
                                                                                   'ScriptControl64_14505.dll',
                                                                                   'umppc14505.dll'],
                                                                    'clear-dll-notifications': True,
                                                                    'clear-hwbp-on-imp-res': True,
                                                                    'clear-hwbp-on-unhook': True,
                                                                    'clear-veh-on-imp-res': True,
                                                                    'clear-veh-on-unhook': True,
                                                                    'disable-pi-callback': True,
                                                                    'encrypt-heap-mode': 'implant',
                                                                    'hide-windows': False,
                                                                    'indirect-syscalls': True,
                                                                    'inproc-patch-amsi': True,
                                                                    'inproc-patch-etw': True,
                                                                    'inproc-restore-etw-control': True,
                                                                    'loader-export': 'DllExecute',
                                                                    'loader-strategy': 'syscalls',
                                                                    'masquerade-thread-stacks': True,
                                                                    'ordinary-export': 'CPlApplet',
                                                                    'patch-etw-control': True,
                                                                    'patch-etw-event': True,
                                                                    'reapply-opsec-on-self-encrypt': True,
                                                                    'self-encrypt-after': 5,
                                                                    'self-encrypt-mode': 'no-stub-timer',
                                                                    'self-encrypt-while-listening': True,
                                                                    'sleep-mode': 'wait-single',
                                                                    'stack-commit-size': 262144,
                                                                    'stomp-pe-header': True,
                                                                    'thread-start-addresses': ['ntdll!RtlUserThreadStart'],
                                                                    'unhook-dlls': ['kernel32.dll',
                                                                                    'ntdll.dll',
                                                                                    'kernelbase.dll',
                                                                                    'winhttp.dll'],
                                                                    'unhook-syscalls': True,
                                                                    'unhook-using-wpm': True,
                                                                    'unhook-via-native': True,
                                                                    'use-syscalls': True,
                                                                    'use-threadpool': True},
                                                          'settings': {'expire-after': 1670803200,
                                                                       'interval': 10,
                                                                       'jitter': 20}},
                                       'listener-name': '2021556',
                                       'mode': 'egress',
                                       'p2p-config': {'aes-128-iv': '876aaskdjdhsagag',
                                                      'aes-128-key': 'LyeA4x7crCQN6+in',
                                                      'p2p-listener-uri': 'smb://myfiles',
                                                      'promote': False,
                                                      'promote-after': 1}}},
 'Plaintext Alphabet': b' wPX])?IeL7y!SaKxkr,sO0Tjl4_hf:C{W.>c$1Hg^u=GYD+Bni<'
                       b'v62z8d3bpRJ(q9MZ/*oNU}[AQmV5tF&;-E\x00'}
```