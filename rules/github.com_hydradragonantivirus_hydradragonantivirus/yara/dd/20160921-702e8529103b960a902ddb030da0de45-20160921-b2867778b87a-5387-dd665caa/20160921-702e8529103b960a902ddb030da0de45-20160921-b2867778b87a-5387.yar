rule _20160921_702e8529103b960a902ddb030da0de45_20160921_b2867778b87a_5387 {
  meta:
    description = "datamaliciousorder - from files 20160921_702e8529103b960a902ddb030da0de45.js, 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash2       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash3       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"

  strings:
    $s1 = "){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s2 = "(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qj\";}" ascii
    $s3 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s4 = "{return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})()" ascii
    $s5 = "f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}