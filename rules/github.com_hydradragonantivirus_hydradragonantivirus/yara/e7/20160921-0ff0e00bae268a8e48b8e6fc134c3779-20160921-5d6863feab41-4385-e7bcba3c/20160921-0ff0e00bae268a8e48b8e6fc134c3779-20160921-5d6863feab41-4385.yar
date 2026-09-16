rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_5d6863feab41_4385 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_5d6863feab411af8217516a1b111aa40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"

  strings:
    $s1 = " \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(func" ascii
    $s2 = " f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp" ascii
    $s3 = " f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"BM" ascii
    $s4 = "unction f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii
    $s5 = "0(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}