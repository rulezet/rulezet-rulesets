rule TTP_XOR_QUAD_CurrentVersionRun_d75f {
  strings:
    $key_d75f = { 84 30 [2] a0 3e [2] 8b 12 [2] a5 30 [2] b1 2b [2] be 31 [2] a0 2c [2] a2 2d [2] b9 2b [2] a5 2c [2] b9 03 }

  condition:
    any of them
}