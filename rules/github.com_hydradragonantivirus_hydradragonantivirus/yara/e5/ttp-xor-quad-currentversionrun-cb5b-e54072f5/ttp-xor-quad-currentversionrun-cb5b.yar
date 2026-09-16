rule TTP_XOR_QUAD_CurrentVersionRun_cb5b {
  strings:
    $key_cb5b = { 98 34 [2] bc 3a [2] 97 16 [2] b9 34 [2] ad 2f [2] a2 35 [2] bc 28 [2] be 29 [2] a5 2f [2] b9 28 [2] a5 07 }

  condition:
    any of them
}