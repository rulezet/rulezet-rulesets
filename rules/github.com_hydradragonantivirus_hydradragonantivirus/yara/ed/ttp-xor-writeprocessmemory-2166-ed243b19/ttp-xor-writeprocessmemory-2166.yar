rule TTP_XOR_WriteProcessMemory_2166 {
  strings:
    $key_2166 = { 76 14 [2] 44 36 [2] 42 03 [2] 6c 03 [2] 53 1f }

  condition:
    any of them
}