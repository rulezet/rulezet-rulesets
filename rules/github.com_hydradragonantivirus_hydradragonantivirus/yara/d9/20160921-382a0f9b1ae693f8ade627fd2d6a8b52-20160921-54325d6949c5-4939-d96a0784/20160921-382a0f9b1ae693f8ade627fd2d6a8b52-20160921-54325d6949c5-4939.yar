rule _20160921_382a0f9b1ae693f8ade627fd2d6a8b52_20160921_54325d6949c5_4939 {
  meta:
    description = "datamaliciousorder - from files 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash2       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash3       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash4       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"

  strings:
    $s1 = "){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";}" ascii
    $s2 = "000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi" ascii
    $s3 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){retur" ascii
    $s4 = " f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"W" ascii
    $s5 = "tion f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}