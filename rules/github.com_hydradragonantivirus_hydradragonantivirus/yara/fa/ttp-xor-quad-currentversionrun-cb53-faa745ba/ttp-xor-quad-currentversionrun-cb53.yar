rule TTP_XOR_QUAD_CurrentVersionRun_cb53 {
  strings:
    $key_cb53 = { 98 3c [2] bc 32 [2] 97 1e [2] b9 3c [2] ad 27 [2] a2 3d [2] bc 20 [2] be 21 [2] a5 27 [2] b9 20 [2] a5 0f }

  condition:
    any of them
}