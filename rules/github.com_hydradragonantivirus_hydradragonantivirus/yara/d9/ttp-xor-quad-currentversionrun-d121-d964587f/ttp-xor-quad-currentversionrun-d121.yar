rule TTP_XOR_QUAD_CurrentVersionRun_d121 {
  strings:
    $key_d121 = { 82 4e [2] a6 40 [2] 8d 6c [2] a3 4e [2] b7 55 [2] b8 4f [2] a6 52 [2] a4 53 [2] bf 55 [2] a3 52 [2] bf 7d }

  condition:
    any of them
}