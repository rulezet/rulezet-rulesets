rule TTP_XOR_QUAD_CurrentVersionRun_cd4d {
  strings:
    $key_cd4d = { 9e 22 [2] ba 2c [2] 91 00 [2] bf 22 [2] ab 39 [2] a4 23 [2] ba 3e [2] b8 3f [2] a3 39 [2] bf 3e [2] a3 11 }

  condition:
    any of them
}