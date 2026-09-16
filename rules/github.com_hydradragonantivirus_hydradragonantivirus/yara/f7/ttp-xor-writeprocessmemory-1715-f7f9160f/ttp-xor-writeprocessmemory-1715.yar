rule TTP_XOR_WriteProcessMemory_1715 {
  strings:
    $key_1715 = { 40 67 [2] 72 45 [2] 74 70 [2] 5a 70 [2] 65 6c }

  condition:
    any of them
}