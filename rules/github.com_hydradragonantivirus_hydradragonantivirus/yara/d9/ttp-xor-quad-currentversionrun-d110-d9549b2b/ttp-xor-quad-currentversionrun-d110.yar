rule TTP_XOR_QUAD_CurrentVersionRun_d110 {
  strings:
    $key_d110 = { 82 7f [2] a6 71 [2] 8d 5d [2] a3 7f [2] b7 64 [2] b8 7e [2] a6 63 [2] a4 62 [2] bf 64 [2] a3 63 [2] bf 4c }

  condition:
    any of them
}