rule TTP_XOR_WriteProcessMemory_7415 {
  strings:
    $key_7415 = { 23 67 [2] 11 45 [2] 17 70 [2] 39 70 [2] 06 6c }

  condition:
    any of them
}