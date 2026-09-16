rule TTP_XOR_QUAD_CurrentVersionRun_e0f4 {
  strings:
    $key_e0f4 = { b3 9b [2] 97 95 [2] bc b9 [2] 92 9b [2] 86 80 [2] 89 9a [2] 97 87 [2] 95 86 [2] 8e 80 [2] 92 87 [2] 8e a8 }

  condition:
    any of them
}