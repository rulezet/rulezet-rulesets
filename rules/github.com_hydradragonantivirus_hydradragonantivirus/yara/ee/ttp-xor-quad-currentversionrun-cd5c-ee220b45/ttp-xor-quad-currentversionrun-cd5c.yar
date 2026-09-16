rule TTP_XOR_QUAD_CurrentVersionRun_cd5c {
  strings:
    $key_cd5c = { 9e 33 [2] ba 3d [2] 91 11 [2] bf 33 [2] ab 28 [2] a4 32 [2] ba 2f [2] b8 2e [2] a3 28 [2] bf 2f [2] a3 00 }

  condition:
    any of them
}