rule TTP_XOR_QUAD_CurrentVersionRun_cd79 {
  strings:
    $key_cd79 = { 9e 16 [2] ba 18 [2] 91 34 [2] bf 16 [2] ab 0d [2] a4 17 [2] ba 0a [2] b8 0b [2] a3 0d [2] bf 0a [2] a3 25 }

  condition:
    any of them
}