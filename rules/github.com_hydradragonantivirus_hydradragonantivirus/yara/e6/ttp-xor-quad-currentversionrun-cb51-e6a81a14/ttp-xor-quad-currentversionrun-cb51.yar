rule TTP_XOR_QUAD_CurrentVersionRun_cb51 {
  strings:
    $key_cb51 = { 98 3e [2] bc 30 [2] 97 1c [2] b9 3e [2] ad 25 [2] a2 3f [2] bc 22 [2] be 23 [2] a5 25 [2] b9 22 [2] a5 0d }

  condition:
    any of them
}