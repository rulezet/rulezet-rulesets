rule TTP_XOR_QUAD_CurrentVersionRun_cd49 {
  strings:
    $key_cd49 = { 9e 26 [2] ba 28 [2] 91 04 [2] bf 26 [2] ab 3d [2] a4 27 [2] ba 3a [2] b8 3b [2] a3 3d [2] bf 3a [2] a3 15 }

  condition:
    any of them
}