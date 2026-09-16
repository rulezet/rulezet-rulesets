rule TTP_XOR_QUAD_CurrentVersionRun_cb6f {
  strings:
    $key_cb6f = { 98 00 [2] bc 0e [2] 97 22 [2] b9 00 [2] ad 1b [2] a2 01 [2] bc 1c [2] be 1d [2] a5 1b [2] b9 1c [2] a5 33 }

  condition:
    any of them
}