rule TTP_XOR_QUAD_CurrentVersionRun_cb56 {
  strings:
    $key_cb56 = { 98 39 [2] bc 37 [2] 97 1b [2] b9 39 [2] ad 22 [2] a2 38 [2] bc 25 [2] be 24 [2] a5 22 [2] b9 25 [2] a5 0a }

  condition:
    any of them
}