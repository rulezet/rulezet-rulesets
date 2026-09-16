rule _20160921_10f44d7e5dfb0603aa30725d24785246_20160921_232b12ddd1b9_481 {
  meta:
    description = "datamaliciousorder - from files 20160921_10f44d7e5dfb0603aa30725d24785246.js, 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js, 20160921_766f6fcbd2a94a55747a3f5b9a204b0e.js, 20160921_7c37cf57d8ed1c10fea15c60dc79c0c8.js, 20160921_832521e32124647e5f9543472346f319.js, 20160921_a05dfc337c4ada28e05759b304eef904.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js, 20160921_ba12dcdd1588a0048542bf1b103073ef.js, 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_d4b576a05afdcd9649d02e422feb16d3.js, 20160921_dcd6ef8585af301daafce3419ba14724.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ded66def256e0559ce1d6d20e6f8663edec045a58bb8ef0ec1038fbd91f7c7c1"
    hash2       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash3       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash4       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"
    hash5       = "7ac34bd929ce60a874936fef08adcce78783c70441a9eff1cd392604bcf45ff7"
    hash6       = "c3acecff4ec35ade7d618cbd511372d6023de7d591317c5e6ce95fc088b8cf6e"
    hash7       = "7d8db496c31215a3730a6ed92a0e2b36ff0fe0e9ddaf7405680d1002474263e1"
    hash8       = "db6a3cf7e8281867bf38b22cce5a945336377679a1a85ee91d365e41ec94182c"
    hash9       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"
    hash10      = "18a1f3c65d9893a27783cb78ff5cd36c757196e35be1977f03c68231e20d9b44"
    hash11      = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash12      = "221c028d5b96ed7d5655800598b47b367ee2d1927826d126b5808db32c9a01f2"
    hash13      = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"
    hash14      = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1  = "fuck(){return \"SUi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MB" ascii
    $s2  = "rn \"CCb\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s3  = "){return \"Wo\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";}" ascii
    $s4  = "unction fuck(){return \"Ar\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){retu" ascii
    $s5  = "on fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s6  = "eturn \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Jg\";})(),(f" ascii
    $s7  = "(){return \"Zy\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";}" ascii
    $s8  = "Av\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s9  = "n fuck(){return \"KVh\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return " ascii
    $s10 = "(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})(),(function fuck()" ascii
    $s11 = "u\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function" ascii
    $s12 = "k(){return \"Xg\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Xw\";}" ascii
    $s13 = "fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv" ascii
    $s14 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"EHo\";})(),(fun" ascii
    $s15 = "(){return \"CCb\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZLd\";" ascii
    $s16 = "ck(){return \"MUs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Mw\"" ascii
    $s17 = " fuck(){return \"Xw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Fv" ascii
    $s18 = "\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"LLv\";})(),(function f" ascii
    $s19 = " \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Ar\";})(),(funct" ascii
    $s20 = "n\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UXf\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}