rule TTP_XOR_QUAD_CurrentVersionRun_cb20 {
  strings:
    $key_cb20 = { 98 4f [2] bc 41 [2] 97 6d [2] b9 4f [2] ad 54 [2] a2 4e [2] bc 53 [2] be 52 [2] a5 54 [2] b9 53 [2] a5 7c }

  condition:
    any of them
}