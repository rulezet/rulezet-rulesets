rule TTP_XOR_QUAD_CurrentVersionRun_cd10 {
  strings:
    $key_cd10 = { 9e 7f [2] ba 71 [2] 91 5d [2] bf 7f [2] ab 64 [2] a4 7e [2] ba 63 [2] b8 62 [2] a3 64 [2] bf 63 [2] a3 4c }

  condition:
    any of them
}