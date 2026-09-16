rule TTP_XOR_QUAD_CurrentVersionRun_cb67 {
  strings:
    $key_cb67 = { 98 08 [2] bc 06 [2] 97 2a [2] b9 08 [2] ad 13 [2] a2 09 [2] bc 14 [2] be 15 [2] a5 13 [2] b9 14 [2] a5 3b }

  condition:
    any of them
}