rule TTP_XOR_QUAD_CurrentVersionRun_cbf9 {
  strings:
    $key_cbf9 = { 98 96 [2] bc 98 [2] 97 b4 [2] b9 96 [2] ad 8d [2] a2 97 [2] bc 8a [2] be 8b [2] a5 8d [2] b9 8a [2] a5 a5 }

  condition:
    any of them
}