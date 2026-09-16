rule TTP_XOR_WriteProcessMemory_1370 {
  strings:
    $key_1370 = { 44 02 [2] 76 20 [2] 70 15 [2] 5e 15 [2] 61 09 }

  condition:
    any of them
}