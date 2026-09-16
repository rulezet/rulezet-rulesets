rule _20160921_d999dcba53f56b5a9c1abcc062fbeb80_20160921_e6569e3fc498_5715 {
  meta:
    description = "datamaliciousorder - from files 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"
    hash2       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"

  strings:
    $s1 = "0(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";}" ascii
    $s2 = "n \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s3 = "h\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s4 = "f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw" ascii
    $s5 = "000(){return \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}