rule TTP_XOR_QUAD_CurrentVersionRun_cd27 {
  strings:
    $key_cd27 = { 9e 48 [2] ba 46 [2] 91 6a [2] bf 48 [2] ab 53 [2] a4 49 [2] ba 54 [2] b8 55 [2] a3 53 [2] bf 54 [2] a3 7b }

  condition:
    any of them
}