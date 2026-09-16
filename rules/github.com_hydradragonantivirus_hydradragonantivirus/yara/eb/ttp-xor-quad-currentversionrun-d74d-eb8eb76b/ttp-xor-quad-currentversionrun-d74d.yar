rule TTP_XOR_QUAD_CurrentVersionRun_d74d {
  strings:
    $key_d74d = { 84 22 [2] a0 2c [2] 8b 00 [2] a5 22 [2] b1 39 [2] be 23 [2] a0 3e [2] a2 3f [2] b9 39 [2] a5 3e [2] b9 11 }

  condition:
    any of them
}