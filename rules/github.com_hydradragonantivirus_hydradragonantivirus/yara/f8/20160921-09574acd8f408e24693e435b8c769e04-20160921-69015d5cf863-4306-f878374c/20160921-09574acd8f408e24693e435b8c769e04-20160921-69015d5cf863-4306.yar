rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_69015d5cf863_4306 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash3       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"

  strings:
    $s1 = "00(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\"" ascii
    $s2 = "WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(functio" ascii
    $s3 = "(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})" ascii
    $s4 = " \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s5 = "f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}