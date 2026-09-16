rule TTP_XOR_QUAD_CurrentVersionRun_d13f {
  strings:
    $key_d13f = { 82 50 [2] a6 5e [2] 8d 72 [2] a3 50 [2] b7 4b [2] b8 51 [2] a6 4c [2] a4 4d [2] bf 4b [2] a3 4c [2] bf 63 }

  condition:
    any of them
}