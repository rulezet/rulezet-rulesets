rule TTP_XOR_QUAD_CurrentVersionRun_cd5b {
  strings:
    $key_cd5b = { 9e 34 [2] ba 3a [2] 91 16 [2] bf 34 [2] ab 2f [2] a4 35 [2] ba 28 [2] b8 29 [2] a3 2f [2] bf 28 [2] a3 07 }

  condition:
    any of them
}