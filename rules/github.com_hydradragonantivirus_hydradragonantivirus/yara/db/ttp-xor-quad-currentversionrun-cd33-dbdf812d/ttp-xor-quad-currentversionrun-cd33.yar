rule TTP_XOR_QUAD_CurrentVersionRun_cd33 {
  strings:
    $key_cd33 = { 9e 5c [2] ba 52 [2] 91 7e [2] bf 5c [2] ab 47 [2] a4 5d [2] ba 40 [2] b8 41 [2] a3 47 [2] bf 40 [2] a3 6f }

  condition:
    any of them
}