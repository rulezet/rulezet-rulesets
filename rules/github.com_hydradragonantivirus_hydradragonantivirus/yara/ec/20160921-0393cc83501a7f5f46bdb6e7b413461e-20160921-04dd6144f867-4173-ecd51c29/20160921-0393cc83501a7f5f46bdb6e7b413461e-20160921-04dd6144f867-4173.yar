rule _20160921_0393cc83501a7f5f46bdb6e7b413461e_20160921_04dd6144f867_4173 {
  meta:
    description = "datamaliciousorder - from files 20160921_0393cc83501a7f5f46bdb6e7b413461e.js, 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_e949fdc198fee477717395093f5853e7.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"
    hash2       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash3       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash4       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash5       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash6       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"
    hash7       = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash8       = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1 = "\"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(functi" ascii
    $s2 = ",(function f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){r" ascii
    $s3 = "){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";}" ascii
    $s4 = "ction f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){retur" ascii
    $s5 = "return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}