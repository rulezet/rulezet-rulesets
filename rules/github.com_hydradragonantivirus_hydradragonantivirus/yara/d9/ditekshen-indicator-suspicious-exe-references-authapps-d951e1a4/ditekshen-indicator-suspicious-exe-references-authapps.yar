rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_References_Authapps: FILE {
  meta:
    description = "Detects executables referencing many authentication apps. Observed in information stealers"
    author      = "ditekSHen"
    id          = "b2c1307d-ac4a-567f-ab14-7c65e16d984e"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L2012-L2021"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "9c730ba532dca023821fd9073bffeecf099a2a956b7715421bd0b4e5e5d4b2cf"
    score       = 40
    quality     = 41
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "WinAuth\\winauth.xml" ascii wide nocase
    $s2 = "Authy Desktop\\Local" ascii wide nocase

  condition:
    uint16(0) == 0x5a4d and all of them
}