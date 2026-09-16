rule TTP_XOR_QUAD_CurrentVersionRun_d04d {
  strings:
    $key_d04d = { 83 22 [2] a7 2c [2] 8c 00 [2] a2 22 [2] b6 39 [2] b9 23 [2] a7 3e [2] a5 3f [2] be 39 [2] a2 3e [2] be 11 }

  condition:
    any of them
}