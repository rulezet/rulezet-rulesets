rule TTP_XOR_WriteProcessMemory_2500 {
  strings:
    $key_2500 = { 72 72 [2] 40 50 [2] 46 65 [2] 68 65 [2] 57 79 }

  condition:
    any of them
}