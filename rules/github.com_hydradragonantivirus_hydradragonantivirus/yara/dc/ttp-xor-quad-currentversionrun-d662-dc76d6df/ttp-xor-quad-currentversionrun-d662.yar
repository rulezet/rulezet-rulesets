rule TTP_XOR_QUAD_CurrentVersionRun_d662 {
  strings:
    $key_d662 = { 85 0d [2] a1 03 [2] 8a 2f [2] a4 0d [2] b0 16 [2] bf 0c [2] a1 11 [2] a3 10 [2] b8 16 [2] a4 11 [2] b8 3e }

  condition:
    any of them
}