rule TTP_XOR_WriteProcessMemory_3066 {
  strings:
    $key_3066 = { 67 14 [2] 55 36 [2] 53 03 [2] 7d 03 [2] 42 1f }

  condition:
    any of them
}