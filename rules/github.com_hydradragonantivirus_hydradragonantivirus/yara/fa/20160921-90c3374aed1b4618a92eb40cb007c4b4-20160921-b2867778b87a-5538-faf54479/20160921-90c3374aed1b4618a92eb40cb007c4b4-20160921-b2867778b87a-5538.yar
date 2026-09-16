rule _20160921_90c3374aed1b4618a92eb40cb007c4b4_20160921_b2867778b87a_5538 {
  meta:
    description = "datamaliciousorder - from files 20160921_90c3374aed1b4618a92eb40cb007c4b4.js, 20160921_b2867778b87ab68774c77840f21eaed0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"
    hash2       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"

  strings:
    $s1 = "\"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(func" ascii
    $s2 = "\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s3 = "on f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Q" ascii
    $s4 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){ret" ascii
    $s5 = "u\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}