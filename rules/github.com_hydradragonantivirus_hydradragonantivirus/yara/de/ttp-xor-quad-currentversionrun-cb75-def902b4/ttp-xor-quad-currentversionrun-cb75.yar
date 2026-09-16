rule TTP_XOR_QUAD_CurrentVersionRun_cb75 {
  strings:
    $key_cb75 = { 98 1a [2] bc 14 [2] 97 38 [2] b9 1a [2] ad 01 [2] a2 1b [2] bc 06 [2] be 07 [2] a5 01 [2] b9 06 [2] a5 29 }

  condition:
    any of them
}