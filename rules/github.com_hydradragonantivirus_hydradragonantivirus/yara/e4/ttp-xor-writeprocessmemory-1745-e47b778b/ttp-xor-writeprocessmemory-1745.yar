rule TTP_XOR_WriteProcessMemory_1745 {
  strings:
    $key_1745 = { 40 37 [2] 72 15 [2] 74 20 [2] 5a 20 [2] 65 3c }

  condition:
    any of them
}