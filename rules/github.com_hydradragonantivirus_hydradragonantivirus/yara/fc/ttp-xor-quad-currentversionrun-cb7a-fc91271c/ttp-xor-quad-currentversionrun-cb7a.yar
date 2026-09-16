rule TTP_XOR_QUAD_CurrentVersionRun_cb7a {
  strings:
    $key_cb7a = { 98 15 [2] bc 1b [2] 97 37 [2] b9 15 [2] ad 0e [2] a2 14 [2] bc 09 [2] be 08 [2] a5 0e [2] b9 09 [2] a5 26 }

  condition:
    any of them
}