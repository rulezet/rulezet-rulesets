rule TTP_XOR_QUAD_CurrentVersionRun_cb1b {
  strings:
    $key_cb1b = { 98 74 [2] bc 7a [2] 97 56 [2] b9 74 [2] ad 6f [2] a2 75 [2] bc 68 [2] be 69 [2] a5 6f [2] b9 68 [2] a5 47 }

  condition:
    any of them
}