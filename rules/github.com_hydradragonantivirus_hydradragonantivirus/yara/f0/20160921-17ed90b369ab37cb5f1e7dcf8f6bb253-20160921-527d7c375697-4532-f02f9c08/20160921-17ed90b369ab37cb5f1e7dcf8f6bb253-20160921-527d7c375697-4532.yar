rule _20160921_17ed90b369ab37cb5f1e7dcf8f6bb253_20160921_527d7c375697_4532 {
  meta:
    description = "datamaliciousorder - from files 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_527d7c3756974f804734da343b6b6f0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash2       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"

  strings:
    $s1 = "return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})()" ascii
    $s2 = "})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})(),(function f000" ascii
    $s3 = " f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s4 = " f000(){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"" ascii
    $s5 = "urn \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OMd\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}