rule TTP_XOR_QUAD_CurrentVersionRun_d132 {
  strings:
    $key_d132 = { 82 5d [2] a6 53 [2] 8d 7f [2] a3 5d [2] b7 46 [2] b8 5c [2] a6 41 [2] a4 40 [2] bf 46 [2] a3 41 [2] bf 6e }

  condition:
    any of them
}