rule _20160921_814eb57aeffc75442964829345cc9f96_20160921_89a260f4d6da_1610 {
  meta:
    description = "datamaliciousorder - from files 20160921_814eb57aeffc75442964829345cc9f96.js, 20160921_89a260f4d6da4d97f251f843cf5e94b0.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2736df4d651a33824aba7abffa7c08414414ffed9f5f27b4b2d81101cfeb7117"
    hash2       = "700f6c802eb024896efe2b22255973b53752a8f129213c9bba2c4f2ebdc53988"
    hash3       = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"

  strings:
    $s1  = "rn \"Vj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s2  = "),(function f000(){return \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(" ascii
    $s3  = "Zu\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s4  = "000(){return \"MMz\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GG" ascii
    $s5  = "urn \"QDg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s6  = "f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Yz" ascii
    $s7  = "})(),(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000" ascii
    $s8  = "ction f000(){return \"Nx\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return " ascii
    $s9  = "})(),(function f000(){return \"Sv\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Iq\";})(),(function f000" ascii
    $s10 = "nction f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){ret" ascii
    $s11 = "\"Sj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(funct" ascii
    $s12 = "(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DYx\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}