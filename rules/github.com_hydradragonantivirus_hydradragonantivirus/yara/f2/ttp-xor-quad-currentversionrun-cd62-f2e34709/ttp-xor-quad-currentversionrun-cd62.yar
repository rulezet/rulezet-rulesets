rule TTP_XOR_QUAD_CurrentVersionRun_cd62 {
  strings:
    $key_cd62 = { 9e 0d [2] ba 03 [2] 91 2f [2] bf 0d [2] ab 16 [2] a4 0c [2] ba 11 [2] b8 10 [2] a3 16 [2] bf 11 [2] a3 3e }

  condition:
    any of them
}