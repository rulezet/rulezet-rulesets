rule TTP_XOR_WriteProcessMemory_1343 {
  strings:
    $key_1343 = { 44 31 [2] 76 13 [2] 70 26 [2] 5e 26 [2] 61 3a }

  condition:
    any of them
}