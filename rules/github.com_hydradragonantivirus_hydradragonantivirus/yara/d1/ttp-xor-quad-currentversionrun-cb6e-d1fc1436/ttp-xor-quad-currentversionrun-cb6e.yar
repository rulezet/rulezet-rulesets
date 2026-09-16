rule TTP_XOR_QUAD_CurrentVersionRun_cb6e {
  strings:
    $key_cb6e = { 98 01 [2] bc 0f [2] 97 23 [2] b9 01 [2] ad 1a [2] a2 00 [2] bc 1d [2] be 1c [2] a5 1a [2] b9 1d [2] a5 32 }

  condition:
    any of them
}