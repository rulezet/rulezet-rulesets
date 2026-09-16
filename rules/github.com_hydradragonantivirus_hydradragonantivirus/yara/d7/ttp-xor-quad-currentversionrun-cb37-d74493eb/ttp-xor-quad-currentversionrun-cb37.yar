rule TTP_XOR_QUAD_CurrentVersionRun_cb37 {
  strings:
    $key_cb37 = { 98 58 [2] bc 56 [2] 97 7a [2] b9 58 [2] ad 43 [2] a2 59 [2] bc 44 [2] be 45 [2] a5 43 [2] b9 44 [2] a5 6b }

  condition:
    any of them
}