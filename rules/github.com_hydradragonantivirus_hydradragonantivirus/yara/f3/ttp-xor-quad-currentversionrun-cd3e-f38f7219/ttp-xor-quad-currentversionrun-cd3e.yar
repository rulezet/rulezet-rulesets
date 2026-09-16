rule TTP_XOR_QUAD_CurrentVersionRun_cd3e {
  strings:
    $key_cd3e = { 9e 51 [2] ba 5f [2] 91 73 [2] bf 51 [2] ab 4a [2] a4 50 [2] ba 4d [2] b8 4c [2] a3 4a [2] bf 4d [2] a3 62 }

  condition:
    any of them
}