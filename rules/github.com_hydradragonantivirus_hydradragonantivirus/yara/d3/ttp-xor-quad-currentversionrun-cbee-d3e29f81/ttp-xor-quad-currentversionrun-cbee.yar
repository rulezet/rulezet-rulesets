rule TTP_XOR_QUAD_CurrentVersionRun_cbee {
  strings:
    $key_cbee = { 98 81 [2] bc 8f [2] 97 a3 [2] b9 81 [2] ad 9a [2] a2 80 [2] bc 9d [2] be 9c [2] a5 9a [2] b9 9d [2] a5 b2 }

  condition:
    any of them
}