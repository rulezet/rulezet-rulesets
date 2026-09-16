rule sig_20160823_d80e8b158f8960b1dabafdeb153de80a {
  meta:
    description = "datamaliciousorder - file 20160823_d80e8b158f8960b1dabafdeb153de80a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d41937f9744906ff11f24a4ab21e967c34dc8bf2c9f822e2c6679d2fc543c42e"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}