rule TTP_XOR_QUAD_CurrentVersionRun_d622 {
  strings:
    $key_d622 = { 85 4d [2] a1 43 [2] 8a 6f [2] a4 4d [2] b0 56 [2] bf 4c [2] a1 51 [2] a3 50 [2] b8 56 [2] a4 51 [2] b8 7e }

  condition:
    any of them
}