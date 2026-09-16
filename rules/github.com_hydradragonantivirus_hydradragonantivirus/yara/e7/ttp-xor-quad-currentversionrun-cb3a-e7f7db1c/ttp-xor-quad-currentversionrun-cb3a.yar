rule TTP_XOR_QUAD_CurrentVersionRun_cb3a {
  strings:
    $key_cb3a = { 98 55 [2] bc 5b [2] 97 77 [2] b9 55 [2] ad 4e [2] a2 54 [2] bc 49 [2] be 48 [2] a5 4e [2] b9 49 [2] a5 66 }

  condition:
    any of them
}