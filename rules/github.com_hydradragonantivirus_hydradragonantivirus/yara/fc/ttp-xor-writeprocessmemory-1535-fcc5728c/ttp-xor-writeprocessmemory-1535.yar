rule TTP_XOR_WriteProcessMemory_1535 {
  strings:
    $key_1535 = { 42 47 [2] 70 65 [2] 76 50 [2] 58 50 [2] 67 4c }

  condition:
    any of them
}