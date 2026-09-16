rule TTP_XOR_QUAD_CurrentVersionRun_d74e {
  strings:
    $key_d74e = { 84 21 [2] a0 2f [2] 8b 03 [2] a5 21 [2] b1 3a [2] be 20 [2] a0 3d [2] a2 3c [2] b9 3a [2] a5 3d [2] b9 12 }

  condition:
    any of them
}