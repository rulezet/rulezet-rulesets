rule TTP_XOR_QUAD_CurrentVersionRun_cd54 {
  strings:
    $key_cd54 = { 9e 3b [2] ba 35 [2] 91 19 [2] bf 3b [2] ab 20 [2] a4 3a [2] ba 27 [2] b8 26 [2] a3 20 [2] bf 27 [2] a3 08 }

  condition:
    any of them
}