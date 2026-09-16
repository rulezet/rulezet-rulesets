rule TTP_XOR_QUAD_CurrentVersionRun_e078 {
  strings:
    $key_e078 = { b3 17 [2] 97 19 [2] bc 35 [2] 92 17 [2] 86 0c [2] 89 16 [2] 97 0b [2] 95 0a [2] 8e 0c [2] 92 0b [2] 8e 24 }

  condition:
    any of them
}