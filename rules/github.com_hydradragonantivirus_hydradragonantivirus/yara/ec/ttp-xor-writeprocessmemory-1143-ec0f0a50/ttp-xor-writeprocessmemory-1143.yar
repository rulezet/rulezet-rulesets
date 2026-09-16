rule TTP_XOR_WriteProcessMemory_1143 {
  strings:
    $key_1143 = { 46 31 [2] 74 13 [2] 72 26 [2] 5c 26 [2] 63 3a }

  condition:
    any of them
}