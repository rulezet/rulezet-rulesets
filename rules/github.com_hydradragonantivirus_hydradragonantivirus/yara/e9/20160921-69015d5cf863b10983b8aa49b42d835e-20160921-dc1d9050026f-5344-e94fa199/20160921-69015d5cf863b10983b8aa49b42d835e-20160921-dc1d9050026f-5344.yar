rule _20160921_69015d5cf863b10983b8aa49b42d835e_20160921_dc1d9050026f_5344 {
  meta:
    description = "datamaliciousorder - from files 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js, 20160921_e1835bc92c4604db194bc49df621cade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash2       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"
    hash3       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"

  strings:
    $s1 = "nction f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s2 = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DNa" ascii
    $s3 = "tion f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return" ascii
    $s4 = "\"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(func" ascii
    $s5 = "urn \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"OUx\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}