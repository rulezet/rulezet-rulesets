rule _20160921_0393cc83501a7f5f46bdb6e7b413461e_20160921_21f60aa0eac9_1766 {
  meta:
    description = "datamaliciousorder - from files 20160921_0393cc83501a7f5f46bdb6e7b413461e.js, 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_5d76de82063e28ac2a0fc9a6ce296761.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"
    hash2       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash3       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"
    hash4       = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"

  strings:
    $s1  = "ion f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s2  = "ction f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){retur" ascii
    $s3  = "\"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s4  = "n \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(f" ascii
    $s5  = ",(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000()" ascii
    $s6  = "000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\"" ascii
    $s7  = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"I" ascii
    $s8  = ")(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii
    $s9  = "Xg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(functio" ascii
    $s10 = "){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"ZIi\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}