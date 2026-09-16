rule TTP_XOR_QUAD_CurrentVersionRun_d047 {
  strings:
    $key_d047 = { 83 28 [2] a7 26 [2] 8c 0a [2] a2 28 [2] b6 33 [2] b9 29 [2] a7 34 [2] a5 35 [2] be 33 [2] a2 34 [2] be 1b }

  condition:
    any of them
}