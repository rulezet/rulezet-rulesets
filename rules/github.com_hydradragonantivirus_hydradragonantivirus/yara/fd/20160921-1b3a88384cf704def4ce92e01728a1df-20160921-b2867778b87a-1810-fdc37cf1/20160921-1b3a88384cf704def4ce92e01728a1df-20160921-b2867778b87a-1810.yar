rule _20160921_1b3a88384cf704def4ce92e01728a1df_20160921_b2867778b87a_1810 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b3a88384cf704def4ce92e01728a1df.js, 20160921_b2867778b87ab68774c77840f21eaed0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc931c610cc8536a2b67001c5b7c93e6dc26026d0daa00576bf3e92b3bd564a7"
    hash2       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"

  strings:
    $s1  = "on f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s2  = ")(),(function f000(){return \"DNa\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NYh\";})(),(function f00" ascii
    $s3  = "function f000(){return \"Lo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Qa\";})(),(function f000(){retu" ascii
    $s4  = "urn \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(fu" ascii
    $s5  = "(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})" ascii
    $s6  = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Vu\";})(),(function f00" ascii
    $s7  = "n f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"T" ascii
    $s8  = "return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})()" ascii
    $s9  = "f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Iq" ascii
    $s10 = "on f000(){return \"RLk\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}