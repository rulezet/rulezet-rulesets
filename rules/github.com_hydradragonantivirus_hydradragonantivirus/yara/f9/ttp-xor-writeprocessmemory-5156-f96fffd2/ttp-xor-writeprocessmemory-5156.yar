rule TTP_XOR_WriteProcessMemory_5156 {
  strings:
    $key_5156 = { 06 24 [2] 34 06 [2] 32 33 [2] 1c 33 [2] 23 2f }

  condition:
    any of them
}