rule TTP_XOR_WriteProcessMemory_5025 {
  strings:
    $key_5025 = { 07 57 [2] 35 75 [2] 33 40 [2] 1d 40 [2] 22 5c }

  condition:
    any of them
}