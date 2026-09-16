rule TTP_XOR_QUAD_CurrentVersionRun_dd4d {
  strings:
    $key_dd4d = { 8e 22 [2] aa 2c [2] 81 00 [2] af 22 [2] bb 39 [2] b4 23 [2] aa 3e [2] a8 3f [2] b3 39 [2] af 3e [2] b3 11 }

  condition:
    any of them
}