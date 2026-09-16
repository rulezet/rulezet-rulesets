rule TTP_XOR_WriteProcessMemory_e246 {
  strings:
    $key_e246 = { b5 34 [2] 87 16 [2] 81 23 [2] af 23 [2] 90 3f }

  condition:
    any of them
}