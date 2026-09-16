rule ESET_Apt_Windows_TA410_Lookback_Decryption: FILE {
  meta:
    description = "Matches encryption/decryption function used by LookBack."
    author      = "ESET Research"
    id          = "91947c6b-f357-5cf8-8522-4dcd517d01cb"
    date        = "2021-10-12"
    modified    = "2022-04-27"
    reference   = "https://github.com/eset/malware-ioc/"
    source_url  = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/ta410/ta410.yar#L189-L254"
    license_url = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/LICENSE"
    logic_hash  = "016dca6be654fcd193acc481e6a998efbb77e7ebd09b26614422be1136dd02c0"
    score       = 75
    quality     = 80
    tags        = "FILE"
    license     = "BSD 2-Clause"
    version     = "1"

  strings:
    $initialize = {
      8B C6                    99                       83 E2 03                 03 C2                    C1 F8 02                 8A C8                    02 C0                    02 C8                    88 4C 34 10              46                       81 FE 00 01 00 00        72 ??
    }
    $generate   = {
      8A 94 1C 10 01 ?? ??        8D 8C 24 10 01 ?? ??        0F B6 C3                    0F B6 44 04 10              32 C2                       02 F0                       0F B6 C6                    03 C8                       0F B6 01                    88 84 1C 10 01 ?? ??        43                          88 11                       81 FB 00 06 00 00           72 ??                     }
    $decrypt    = {
      0F B6 C6                    8D 8C 24 10 01 ?? ??        03 C8                       8A 19                       8A C3                       02 C6                       FE C6                       02 F8                       0F B6 C7                    8A 94 04 10 01 ?? ??        88 9C 04 10 01 ?? ??        88 11                       0F B6 C2                    0F B6 CB                    33 C8                       8A 84 0C 10 01 ?? ??        30 04 2E                    46                          3B F7                       7C ??                     }

  condition:
    uint16(0) == 0x5a4d and all of them
}