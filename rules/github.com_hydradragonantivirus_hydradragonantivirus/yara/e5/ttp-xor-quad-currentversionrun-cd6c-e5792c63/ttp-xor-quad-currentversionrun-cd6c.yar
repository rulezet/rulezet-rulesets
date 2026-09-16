rule TTP_XOR_QUAD_CurrentVersionRun_cd6c {
  strings:
    $key_cd6c = { 9e 03 [2] ba 0d [2] 91 21 [2] bf 03 [2] ab 18 [2] a4 02 [2] ba 1f [2] b8 1e [2] a3 18 [2] bf 1f [2] a3 30 }

  condition:
    any of them
}