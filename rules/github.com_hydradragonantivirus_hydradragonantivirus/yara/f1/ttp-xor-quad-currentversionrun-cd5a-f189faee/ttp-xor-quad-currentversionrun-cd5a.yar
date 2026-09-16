rule TTP_XOR_QUAD_CurrentVersionRun_cd5a {
  strings:
    $key_cd5a = { 9e 35 [2] ba 3b [2] 91 17 [2] bf 35 [2] ab 2e [2] a4 34 [2] ba 29 [2] b8 28 [2] a3 2e [2] bf 29 [2] a3 06 }

  condition:
    any of them
}