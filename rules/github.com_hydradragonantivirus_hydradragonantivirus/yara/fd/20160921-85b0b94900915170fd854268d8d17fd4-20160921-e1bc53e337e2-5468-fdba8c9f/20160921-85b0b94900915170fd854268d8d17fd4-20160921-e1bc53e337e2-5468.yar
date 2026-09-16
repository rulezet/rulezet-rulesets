rule _20160921_85b0b94900915170fd854268d8d17fd4_20160921_e1bc53e337e2_5468 {
  meta:
    description = "datamaliciousorder - from files 20160921_85b0b94900915170fd854268d8d17fd4.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"
    hash2       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"

  strings:
    $s1 = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(" ascii
    $s2 = "f000(){return \"ZFe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"G" ascii
    $s3 = "eturn \"KDh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Do\";})()," ascii
    $s4 = ")(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s5 = "\"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}