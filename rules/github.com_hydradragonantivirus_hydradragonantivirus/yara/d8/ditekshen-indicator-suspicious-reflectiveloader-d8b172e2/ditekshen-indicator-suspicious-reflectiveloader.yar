import "pe"
rule DITEKSHEN_INDICATOR_SUSPICIOUS_Reflectiveloader: FILE {
  meta:
    description = "Detects Reflective DLL injection artifacts"
    author      = "ditekSHen"
    id          = "b7bd9184-48f8-5ad8-a234-632e4ec9814d"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L29-L43"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "540a48f98652c84b09f1076c2e2fca680781f533c936d602809179469a850ba0"
    score       = 40
    quality     = 45
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "_ReflectiveLoader@" ascii wide
    $s2 = "ReflectiveLoader@" ascii wide

  condition:
    uint16(0) == 0x5a4d and (1 of them or (pe.exports("ReflectiveLoader@4") or pe.exports("_ReflectiveLoader@4") or pe.exports("ReflectiveLoader")))
}