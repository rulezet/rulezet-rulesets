rule TTP_XOR_QUAD_CurrentVersionRun_cb21 {
  strings:
    $key_cb21 = { 98 4e [2] bc 40 [2] 97 6c [2] b9 4e [2] ad 55 [2] a2 4f [2] bc 52 [2] be 53 [2] a5 55 [2] b9 52 [2] a5 7d }

  condition:
    any of them
}