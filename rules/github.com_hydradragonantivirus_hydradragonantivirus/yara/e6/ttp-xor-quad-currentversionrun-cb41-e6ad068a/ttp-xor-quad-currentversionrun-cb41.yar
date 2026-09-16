rule TTP_XOR_QUAD_CurrentVersionRun_cb41 {
  strings:
    $key_cb41 = { 98 2e [2] bc 20 [2] 97 0c [2] b9 2e [2] ad 35 [2] a2 2f [2] bc 32 [2] be 33 [2] a5 35 [2] b9 32 [2] a5 1d }

  condition:
    any of them
}