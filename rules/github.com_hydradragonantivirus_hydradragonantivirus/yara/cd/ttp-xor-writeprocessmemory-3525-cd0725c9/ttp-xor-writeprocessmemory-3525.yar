rule TTP_XOR_WriteProcessMemory_3525 {
  strings:
    $key_3525 = { 62 57 [2] 50 75 [2] 56 40 [2] 78 40 [2] 47 5c }

  condition:
    any of them
}