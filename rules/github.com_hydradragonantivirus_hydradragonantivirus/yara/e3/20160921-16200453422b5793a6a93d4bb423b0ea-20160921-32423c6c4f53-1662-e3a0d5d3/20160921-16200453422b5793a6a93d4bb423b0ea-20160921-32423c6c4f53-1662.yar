rule _20160921_16200453422b5793a6a93d4bb423b0ea_20160921_32423c6c4f53_1662 {
  meta:
    description = "datamaliciousorder - from files 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash2       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash3       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"

  strings:
    $s1  = "),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(),(function f000()" ascii
    $s2  = "nction f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s3  = "\"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})(),(func" ascii
    $s4  = "00(){return \"PTs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\"" ascii
    $s5  = "return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})()" ascii
    $s6  = "){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})" ascii
    $s7  = "0(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";" ascii
    $s8  = ",(function f000(){return \"ZIi\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){" ascii
    $s9  = "ction f000(){return \"Tn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s10 = "c\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"OMd\";})(),(function " ascii
    $s11 = "n \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"PTi\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}