rule TTP_XOR_QUAD_CurrentVersionRun_cd52 {
  strings:
    $key_cd52 = { 9e 3d [2] ba 33 [2] 91 1f [2] bf 3d [2] ab 26 [2] a4 3c [2] ba 21 [2] b8 20 [2] a3 26 [2] bf 21 [2] a3 0e }

  condition:
    any of them
}