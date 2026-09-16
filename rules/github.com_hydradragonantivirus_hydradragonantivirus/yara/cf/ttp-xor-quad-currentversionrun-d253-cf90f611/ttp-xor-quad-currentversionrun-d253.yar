rule TTP_XOR_QUAD_CurrentVersionRun_d253 {
  strings:
    $key_d253 = { 81 3c [2] a5 32 [2] 8e 1e [2] a0 3c [2] b4 27 [2] bb 3d [2] a5 20 [2] a7 21 [2] bc 27 [2] a0 20 [2] bc 0f }

  condition:
    any of them
}