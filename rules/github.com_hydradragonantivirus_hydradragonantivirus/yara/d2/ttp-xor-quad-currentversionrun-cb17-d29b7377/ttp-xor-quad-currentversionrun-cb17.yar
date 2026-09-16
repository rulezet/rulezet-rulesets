rule TTP_XOR_QUAD_CurrentVersionRun_cb17 {
  strings:
    $key_cb17 = { 98 78 [2] bc 76 [2] 97 5a [2] b9 78 [2] ad 63 [2] a2 79 [2] bc 64 [2] be 65 [2] a5 63 [2] b9 64 [2] a5 4b }

  condition:
    any of them
}