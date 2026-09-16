rule TTP_XOR_QUAD_CurrentVersionRun_cb08 {
  strings:
    $key_cb08 = { 98 67 [2] bc 69 [2] 97 45 [2] b9 67 [2] ad 7c [2] a2 66 [2] bc 7b [2] be 7a [2] a5 7c [2] b9 7b [2] a5 54 }

  condition:
    any of them
}