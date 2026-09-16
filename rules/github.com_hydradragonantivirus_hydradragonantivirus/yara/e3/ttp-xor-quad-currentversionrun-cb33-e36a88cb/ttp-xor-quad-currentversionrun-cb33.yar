rule TTP_XOR_QUAD_CurrentVersionRun_cb33 {
  strings:
    $key_cb33 = { 98 5c [2] bc 52 [2] 97 7e [2] b9 5c [2] ad 47 [2] a2 5d [2] bc 40 [2] be 41 [2] a5 47 [2] b9 40 [2] a5 6f }

  condition:
    any of them
}