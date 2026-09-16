rule TTP_XOR_QUAD_CurrentVersionRun_d13c {
  strings:
    $key_d13c = { 82 53 [2] a6 5d [2] 8d 71 [2] a3 53 [2] b7 48 [2] b8 52 [2] a6 4f [2] a4 4e [2] bf 48 [2] a3 4f [2] bf 60 }

  condition:
    any of them
}