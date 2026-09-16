rule TTP_XOR_QUAD_CurrentVersionRun_cb03 {
  strings:
    $key_cb03 = { 98 6c [2] bc 62 [2] 97 4e [2] b9 6c [2] ad 77 [2] a2 6d [2] bc 70 [2] be 71 [2] a5 77 [2] b9 70 [2] a5 5f }

  condition:
    any of them
}