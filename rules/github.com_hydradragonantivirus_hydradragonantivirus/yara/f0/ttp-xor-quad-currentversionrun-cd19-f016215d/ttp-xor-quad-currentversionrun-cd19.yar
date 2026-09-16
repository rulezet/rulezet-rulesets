rule TTP_XOR_QUAD_CurrentVersionRun_cd19 {
  strings:
    $key_cd19 = { 9e 76 [2] ba 78 [2] 91 54 [2] bf 76 [2] ab 6d [2] a4 77 [2] ba 6a [2] b8 6b [2] a3 6d [2] bf 6a [2] a3 45 }

  condition:
    any of them
}