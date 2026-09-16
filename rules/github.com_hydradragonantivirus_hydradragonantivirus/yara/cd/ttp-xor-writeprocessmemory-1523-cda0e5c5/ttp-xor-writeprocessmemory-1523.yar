rule TTP_XOR_WriteProcessMemory_1523 {
  strings:
    $key_1523 = { 42 51 [2] 70 73 [2] 76 46 [2] 58 46 [2] 67 5a }

  condition:
    any of them
}