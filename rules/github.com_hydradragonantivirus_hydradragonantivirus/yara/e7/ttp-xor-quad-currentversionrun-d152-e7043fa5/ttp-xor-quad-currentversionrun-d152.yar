rule TTP_XOR_QUAD_CurrentVersionRun_d152 {
  strings:
    $key_d152 = { 82 3d [2] a6 33 [2] 8d 1f [2] a3 3d [2] b7 26 [2] b8 3c [2] a6 21 [2] a4 20 [2] bf 26 [2] a3 21 [2] bf 0e }

  condition:
    any of them
}