rule TTP_XOR_QUAD_CurrentVersionRun_e058 {
  strings:
    $key_e058 = { b3 37 [2] 97 39 [2] bc 15 [2] 92 37 [2] 86 2c [2] 89 36 [2] 97 2b [2] 95 2a [2] 8e 2c [2] 92 2b [2] 8e 04 }

  condition:
    any of them
}