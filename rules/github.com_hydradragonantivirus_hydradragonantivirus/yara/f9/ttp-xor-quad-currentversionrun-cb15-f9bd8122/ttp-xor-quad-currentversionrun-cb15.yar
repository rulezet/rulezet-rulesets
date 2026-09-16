rule TTP_XOR_QUAD_CurrentVersionRun_cb15 {
  strings:
    $key_cb15 = { 98 7a [2] bc 74 [2] 97 58 [2] b9 7a [2] ad 61 [2] a2 7b [2] bc 66 [2] be 67 [2] a5 61 [2] b9 66 [2] a5 49 }

  condition:
    any of them
}