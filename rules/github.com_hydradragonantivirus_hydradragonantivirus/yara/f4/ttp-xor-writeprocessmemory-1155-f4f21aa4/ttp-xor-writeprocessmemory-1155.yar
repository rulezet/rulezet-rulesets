rule TTP_XOR_WriteProcessMemory_1155 {
  strings:
    $key_1155 = { 46 27 [2] 74 05 [2] 72 30 [2] 5c 30 [2] 63 2c }

  condition:
    any of them
}