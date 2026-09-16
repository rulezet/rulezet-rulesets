rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_5f0fd6cffcc7_4386 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"

  strings:
    $s1 = "n \"Oh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(fun" ascii
    $s2 = "n f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s3 = "000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj" ascii
    $s4 = "000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj" ascii
    $s5 = "ction f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}