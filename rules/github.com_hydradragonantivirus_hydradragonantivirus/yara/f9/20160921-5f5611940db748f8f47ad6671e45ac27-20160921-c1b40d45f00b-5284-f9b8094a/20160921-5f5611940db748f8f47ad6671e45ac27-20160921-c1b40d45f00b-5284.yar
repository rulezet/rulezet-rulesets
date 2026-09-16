rule _20160921_5f5611940db748f8f47ad6671e45ac27_20160921_c1b40d45f00b_5284 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash2       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"

  strings:
    $s1 = "00(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Kw\"" ascii
    $s2 = "nction f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){ret" ascii
    $s3 = "unction f000(){return \"QDg\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){re" ascii
    $s4 = ";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f0" ascii
    $s5 = "MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}