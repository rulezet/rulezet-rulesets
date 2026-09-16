rule TTP_XOR_QUAD_CurrentVersionRun_cd1d {
  strings:
    $key_cd1d = { 9e 72 [2] ba 7c [2] 91 50 [2] bf 72 [2] ab 69 [2] a4 73 [2] ba 6e [2] b8 6f [2] a3 69 [2] bf 6e [2] a3 41 }

  condition:
    any of them
}