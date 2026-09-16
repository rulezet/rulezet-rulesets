rule TTP_XOR_QUAD_CurrentVersionRun_d171 {
  strings:
    $key_d171 = { 82 1e [2] a6 10 [2] 8d 3c [2] a3 1e [2] b7 05 [2] b8 1f [2] a6 02 [2] a4 03 [2] bf 05 [2] a3 02 [2] bf 2d }

  condition:
    any of them
}