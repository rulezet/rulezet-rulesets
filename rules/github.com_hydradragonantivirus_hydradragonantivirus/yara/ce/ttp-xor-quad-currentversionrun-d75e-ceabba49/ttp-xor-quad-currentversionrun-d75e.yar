rule TTP_XOR_QUAD_CurrentVersionRun_d75e {
  strings:
    $key_d75e = { 84 31 [2] a0 3f [2] 8b 13 [2] a5 31 [2] b1 2a [2] be 30 [2] a0 2d [2] a2 2c [2] b9 2a [2] a5 2d [2] b9 02 }

  condition:
    any of them
}