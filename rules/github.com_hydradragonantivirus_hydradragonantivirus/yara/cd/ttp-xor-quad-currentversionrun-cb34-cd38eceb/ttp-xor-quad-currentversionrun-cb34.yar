rule TTP_XOR_QUAD_CurrentVersionRun_cb34 {
  strings:
    $key_cb34 = { 98 5b [2] bc 55 [2] 97 79 [2] b9 5b [2] ad 40 [2] a2 5a [2] bc 47 [2] be 46 [2] a5 40 [2] b9 47 [2] a5 68 }

  condition:
    any of them
}