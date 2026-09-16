rule TTP_XOR_QUAD_CurrentVersionRun_cd03 {
  strings:
    $key_cd03 = { 9e 6c [2] ba 62 [2] 91 4e [2] bf 6c [2] ab 77 [2] a4 6d [2] ba 70 [2] b8 71 [2] a3 77 [2] bf 70 [2] a3 5f }

  condition:
    any of them
}