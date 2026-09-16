rule TTP_XOR_QUAD_CurrentVersionRun_cb1a {
  strings:
    $key_cb1a = { 98 75 [2] bc 7b [2] 97 57 [2] b9 75 [2] ad 6e [2] a2 74 [2] bc 69 [2] be 68 [2] a5 6e [2] b9 69 [2] a5 46 }

  condition:
    any of them
}