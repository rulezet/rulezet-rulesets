rule TTP_XOR_WriteProcessMemory_1115 {
  strings:
    $key_1115 = { 46 67 [2] 74 45 [2] 72 70 [2] 5c 70 [2] 63 6c }

  condition:
    any of them
}