rule _20160921_527d7c3756974f804734da343b6b6f0e_20160921_7f829eb25609_5172 {
  meta:
    description = "datamaliciousorder - from files 20160921_527d7c3756974f804734da343b6b6f0e.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"
    hash2       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"

  strings:
    $s1 = "eturn \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(" ascii
    $s2 = " \"Nv\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s3 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f" ascii
    $s4 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii
    $s5 = "nction f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}