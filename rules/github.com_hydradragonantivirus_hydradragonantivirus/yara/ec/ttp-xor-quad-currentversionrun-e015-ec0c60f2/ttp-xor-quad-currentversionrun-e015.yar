rule TTP_XOR_QUAD_CurrentVersionRun_e015 {
  strings:
    $key_e015 = { b3 7a [2] 97 74 [2] bc 58 [2] 92 7a [2] 86 61 [2] 89 7b [2] 97 66 [2] 95 67 [2] 8e 61 [2] 92 66 [2] 8e 49 }

  condition:
    any of them
}