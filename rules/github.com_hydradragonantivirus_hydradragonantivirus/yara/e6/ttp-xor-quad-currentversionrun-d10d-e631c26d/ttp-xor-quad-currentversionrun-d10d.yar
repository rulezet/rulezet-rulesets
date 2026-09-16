rule TTP_XOR_QUAD_CurrentVersionRun_d10d {
  strings:
    $key_d10d = { 82 62 [2] a6 6c [2] 8d 40 [2] a3 62 [2] b7 79 [2] b8 63 [2] a6 7e [2] a4 7f [2] bf 79 [2] a3 7e [2] bf 51 }

  condition:
    any of them
}