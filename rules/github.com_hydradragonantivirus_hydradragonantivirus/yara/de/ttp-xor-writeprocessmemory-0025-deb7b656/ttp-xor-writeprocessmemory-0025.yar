rule TTP_XOR_WriteProcessMemory_0025 {
  strings:
    $key_0025 = { 57 57 [2] 65 75 [2] 63 40 [2] 4d 40 [2] 72 5c }

  condition:
    any of them
}