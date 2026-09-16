rule TTP_XOR_QUAD_CurrentVersionRun_d05f {
  strings:
    $key_d05f = { 83 30 [2] a7 3e [2] 8c 12 [2] a2 30 [2] b6 2b [2] b9 31 [2] a7 2c [2] a5 2d [2] be 2b [2] a2 2c [2] be 03 }

  condition:
    any of them
}