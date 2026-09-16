rule TTP_XOR_QUAD_CurrentVersionRun_cd2d {
  strings:
    $key_cd2d = { 9e 42 [2] ba 4c [2] 91 60 [2] bf 42 [2] ab 59 [2] a4 43 [2] ba 5e [2] b8 5f [2] a3 59 [2] bf 5e [2] a3 71 }

  condition:
    any of them
}