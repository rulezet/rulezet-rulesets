rule TTP_XOR_QUAD_CurrentVersionRun_cb4d {
  strings:
    $key_cb4d = { 98 22 [2] bc 2c [2] 97 00 [2] b9 22 [2] ad 39 [2] a2 23 [2] bc 3e [2] be 3f [2] a5 39 [2] b9 3e [2] a5 11 }

  condition:
    any of them
}