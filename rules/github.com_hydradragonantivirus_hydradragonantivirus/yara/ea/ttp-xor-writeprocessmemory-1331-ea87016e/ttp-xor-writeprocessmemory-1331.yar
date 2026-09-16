rule TTP_XOR_WriteProcessMemory_1331 {
  strings:
    $key_1331 = { 44 43 [2] 76 61 [2] 70 54 [2] 5e 54 [2] 61 48 }

  condition:
    any of them
}