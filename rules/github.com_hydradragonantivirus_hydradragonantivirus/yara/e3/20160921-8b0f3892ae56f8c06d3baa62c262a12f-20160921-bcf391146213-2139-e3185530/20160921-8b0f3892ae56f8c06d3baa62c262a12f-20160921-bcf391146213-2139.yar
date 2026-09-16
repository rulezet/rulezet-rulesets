rule _20160921_8b0f3892ae56f8c06d3baa62c262a12f_20160921_bcf391146213_2139 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160921_bcf3911462135150c96c6b8eccf51628.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash2       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"

  strings:
    $s1 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return" ascii
    $s2 = "n \"Yi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(func" ascii
    $s3 = "{return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(" ascii
    $s4 = "(){return \"DAp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";" ascii
    $s5 = "\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function" ascii
    $s6 = "eturn \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wb\";})()," ascii
    $s7 = "nction f000(){return \"Oh\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"MDb\";})(),(function f000(){retur" ascii
    $s8 = "nction f000(){return \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Qa\";})(),(function f000(){retu" ascii
    $s9 = "{return \"Vj\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}