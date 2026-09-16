rule TTP_XOR_QUAD_CurrentVersionRun_d053 {
  strings:
    $key_d053 = { 83 3c [2] a7 32 [2] 8c 1e [2] a2 3c [2] b6 27 [2] b9 3d [2] a7 20 [2] a5 21 [2] be 27 [2] a2 20 [2] be 0f }

  condition:
    any of them
}