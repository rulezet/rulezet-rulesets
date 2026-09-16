import "pe"
rule FileShield_ren: Packer PEiD {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 50 1E EB ?? 90 00 00 8B D8 }

  condition:
    $a0 at pe.entry_point
}