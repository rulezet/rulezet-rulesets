rule SIGNATURE_BASE_PUA_VULN_Driver_Razerinc_Rzpnk_Rzpnk_93D8: FILE {
  meta:
    description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - rzpnk.sys"
    author      = "Florian Roth"
    id          = "d300e7a0-b24b-5d52-b850-0aab145b33c5"
    date        = "2023-06-14"
    modified    = "2023-12-05"
    reference   = "https://github.com/magicsword-io/LOLDrivers"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/yara-rules_vuln_drivers_strict.yar#L5257-L5277"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    hash        = "93d873cdf23d5edc622b74f9544cac7fe247d7a68e1e2a7bf2879fad97a3ae63"
    logic_hash  = "cf0c6c37c0ffdc3b9de4a2756f1eae8dde74dad69e5e1a98e0593d64ea0d701f"
    score       = 40
    quality     = 85
    tags        = "FILE"

  strings:
    $ = { 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e [1-8] 00 52 00 61 00 7a 00 65 00 72 00 20 00 4f 00 76 00 65 00 72 00 6c 00 61 00 79 00 20 00 53 00 75 00 70 00 70 00 6f 00 72 00 74 }
    $ = { 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 [1-8] 00 52 00 61 00 7a 00 65 00 72 00 2c 00 20 00 49 00 6e 00 63 00 2e }
    $ = { 00 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e [1-8] 00 31 00 2e 00 30 00 2e 00 31 00 32 00 2e 00 31 00 30 00 31 00 35 00 35 }
    $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e [1-8] 00 31 00 2e 00 30 00 2e 00 31 00 32 00 2e 00 31 00 30 00 31 00 35 00 35 }
    $ = { 00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 [1-8] 00 52 00 7a 00 70 00 6e 00 6b }
    $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 [1-8] 00 52 00 7a 00 70 00 6e 00 6b }
    $ = { 00 4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 [1-8] 00 52 00 7a 00 70 00 6e 00 6b 00 2e 00 73 00 79 00 73 }
    $ = { 00 4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 [1-8] 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 32 00 30 00 31 00 30 00 2d 00 32 00 30 00 31 00 37 00 2e 00 20 00 52 00 61 00 7a 00 65 00 72 00 2c 00 20 00 49 00 6e 00 63 00 2e }

  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and all of them
}