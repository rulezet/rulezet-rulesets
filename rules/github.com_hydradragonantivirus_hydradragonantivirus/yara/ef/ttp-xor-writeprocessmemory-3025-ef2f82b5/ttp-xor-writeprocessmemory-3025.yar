rule TTP_XOR_WriteProcessMemory_3025 {
  strings:
    $key_3025 = { 67 57 [2] 55 75 [2] 53 40 [2] 7d 40 [2] 42 5c }

  condition:
    any of them
}