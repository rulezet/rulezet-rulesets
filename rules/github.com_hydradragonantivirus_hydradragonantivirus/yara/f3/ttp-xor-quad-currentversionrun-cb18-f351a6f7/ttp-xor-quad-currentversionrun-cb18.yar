rule TTP_XOR_QUAD_CurrentVersionRun_cb18 {
  strings:
    $key_cb18 = { 98 77 [2] bc 79 [2] 97 55 [2] b9 77 [2] ad 6c [2] a2 76 [2] bc 6b [2] be 6a [2] a5 6c [2] b9 6b [2] a5 44 }

  condition:
    any of them
}