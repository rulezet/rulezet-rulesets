rule TTP_XOR_QUAD_CurrentVersionRun_cb35 {
  strings:
    $key_cb35 = { 98 5a [2] bc 54 [2] 97 78 [2] b9 5a [2] ad 41 [2] a2 5b [2] bc 46 [2] be 47 [2] a5 41 [2] b9 46 [2] a5 69 }

  condition:
    any of them
}