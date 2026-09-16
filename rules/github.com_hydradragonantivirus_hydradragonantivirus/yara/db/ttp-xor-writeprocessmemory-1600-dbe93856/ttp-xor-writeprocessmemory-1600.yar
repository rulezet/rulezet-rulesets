rule TTP_XOR_WriteProcessMemory_1600 {
  strings:
    $key_1600 = { 41 72 [2] 73 50 [2] 75 65 [2] 5b 65 [2] 64 79 }

  condition:
    any of them
}