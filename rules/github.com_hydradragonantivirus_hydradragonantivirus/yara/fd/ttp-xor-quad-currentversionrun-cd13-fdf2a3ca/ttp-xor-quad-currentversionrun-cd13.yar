rule TTP_XOR_QUAD_CurrentVersionRun_cd13 {
  strings:
    $key_cd13 = { 9e 7c [2] ba 72 [2] 91 5e [2] bf 7c [2] ab 67 [2] a4 7d [2] ba 60 [2] b8 61 [2] a3 67 [2] bf 60 [2] a3 4f }

  condition:
    any of them
}