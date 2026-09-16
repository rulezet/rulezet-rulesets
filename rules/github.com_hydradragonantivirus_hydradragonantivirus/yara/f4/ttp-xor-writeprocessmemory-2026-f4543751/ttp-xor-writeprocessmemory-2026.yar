rule TTP_XOR_WriteProcessMemory_2026 {
  strings:
    $key_2026 = { 77 54 [2] 45 76 [2] 43 43 [2] 6d 43 [2] 52 5f }

  condition:
    any of them
}