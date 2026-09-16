rule TTP_XOR_WriteProcessMemory_5415 {
  strings:
    $key_5415 = { 03 67 [2] 31 45 [2] 37 70 [2] 19 70 [2] 26 6c }

  condition:
    any of them
}