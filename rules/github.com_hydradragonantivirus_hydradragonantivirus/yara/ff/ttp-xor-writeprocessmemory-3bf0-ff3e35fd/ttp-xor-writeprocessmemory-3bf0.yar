rule TTP_XOR_WriteProcessMemory_3bf0 {
  strings:
    $key_3bf0 = { 6c 82 [2] 5e a0 [2] 58 95 [2] 76 95 [2] 49 89 }

  condition:
    any of them
}