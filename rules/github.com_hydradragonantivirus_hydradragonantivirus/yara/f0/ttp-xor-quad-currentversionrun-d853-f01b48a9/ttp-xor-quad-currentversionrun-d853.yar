rule TTP_XOR_QUAD_CurrentVersionRun_d853 {
  strings:
    $key_d853 = { 8b 3c [2] af 32 [2] 84 1e [2] aa 3c [2] be 27 [2] b1 3d [2] af 20 [2] ad 21 [2] b6 27 [2] aa 20 [2] b6 0f }

  condition:
    any of them
}