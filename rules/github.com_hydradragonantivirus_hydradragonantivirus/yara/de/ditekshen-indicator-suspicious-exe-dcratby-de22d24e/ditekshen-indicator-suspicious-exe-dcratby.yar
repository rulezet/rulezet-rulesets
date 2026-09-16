rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Dcratby: FILE {
  meta:
    description = "Detects executables containing the string DcRatBy"
    author      = "ditekSHen"
    id          = "d8408cc0-0245-59b7-9134-1f4edd811df7"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L1504-L1512"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "1a0f863fb71c84a9a01c3f07da0fdff9ea06b061f85532ac523d6a5d1e0e1e11"
    score       = 40
    quality     = 45
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "DcRatBy" ascii wide

  condition:
    uint16(0) == 0x5a4d and all of them
}