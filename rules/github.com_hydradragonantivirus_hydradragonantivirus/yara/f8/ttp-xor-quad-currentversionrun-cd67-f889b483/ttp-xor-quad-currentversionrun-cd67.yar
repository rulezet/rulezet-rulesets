rule TTP_XOR_QUAD_CurrentVersionRun_cd67 {
  strings:
    $key_cd67 = { 9e 08 [2] ba 06 [2] 91 2a [2] bf 08 [2] ab 13 [2] a4 09 [2] ba 14 [2] b8 15 [2] a3 13 [2] bf 14 [2] a3 3b }

  condition:
    any of them
}