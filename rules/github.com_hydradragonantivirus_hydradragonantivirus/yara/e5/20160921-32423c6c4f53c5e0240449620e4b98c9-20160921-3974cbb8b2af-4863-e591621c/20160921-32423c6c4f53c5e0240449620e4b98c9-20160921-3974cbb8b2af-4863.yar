rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_3974cbb8b2af_4863 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_99369f59b90fb2df18b8570f0403febc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash3       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"

  strings:
    $s1 = "(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";" ascii
    $s2 = "ction f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s3 = "rn \"KDh\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s4 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\"" ascii
    $s5 = "(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}