rule TTP_XOR_QUAD_CurrentVersionRun_e065 {
  strings:
    $key_e065 = { b3 0a [2] 97 04 [2] bc 28 [2] 92 0a [2] 86 11 [2] 89 0b [2] 97 16 [2] 95 17 [2] 8e 11 [2] 92 16 [2] 8e 39 }

  condition:
    any of them
}