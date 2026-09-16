rule sig_20160823_e0fc27e31ad9f76aab1a87496eb5bd92 {
  meta:
    description = "datamaliciousorder - file 20160823_e0fc27e31ad9f76aab1a87496eb5bd92.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "508c04b849a4ae1414dee9bedd2358216d908f12c3cc7e761ab31ab636779e7f"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}