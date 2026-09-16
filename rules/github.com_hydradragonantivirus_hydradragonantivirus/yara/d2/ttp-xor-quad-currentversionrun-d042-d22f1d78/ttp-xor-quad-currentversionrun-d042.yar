rule TTP_XOR_QUAD_CurrentVersionRun_d042 {
  strings:
    $key_d042 = { 83 2d [2] a7 23 [2] 8c 0f [2] a2 2d [2] b6 36 [2] b9 2c [2] a7 31 [2] a5 30 [2] be 36 [2] a2 31 [2] be 1e }

  condition:
    any of them
}