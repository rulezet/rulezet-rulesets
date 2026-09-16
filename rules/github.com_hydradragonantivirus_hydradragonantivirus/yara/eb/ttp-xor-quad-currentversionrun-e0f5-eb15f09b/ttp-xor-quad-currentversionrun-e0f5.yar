rule TTP_XOR_QUAD_CurrentVersionRun_e0f5 {
  strings:
    $key_e0f5 = { b3 9a [2] 97 94 [2] bc b8 [2] 92 9a [2] 86 81 [2] 89 9b [2] 97 86 [2] 95 87 [2] 8e 81 [2] 92 86 [2] 8e a9 }

  condition:
    any of them
}