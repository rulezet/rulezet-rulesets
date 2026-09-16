rule TTP_XOR_QUAD_CurrentVersionRun_cb02 {
  strings:
    $key_cb02 = { 98 6d [2] bc 63 [2] 97 4f [2] b9 6d [2] ad 76 [2] a2 6c [2] bc 71 [2] be 70 [2] a5 76 [2] b9 71 [2] a5 5e }

  condition:
    any of them
}