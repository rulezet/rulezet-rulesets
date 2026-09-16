rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_3974cbb8b2af_3604 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash3       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"

  strings:
    $s1 = "unction f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){retu" ascii
    $s2 = "{return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(" ascii
    $s3 = "n \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s4 = ";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s5 = "000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"WIj" ascii
    $s6 = "ion f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}