rule TTP_XOR_WriteProcessMemory_7525 {
  strings:
    $key_7525 = { 22 57 [2] 10 75 [2] 16 40 [2] 38 40 [2] 07 5c }

  condition:
    any of them
}