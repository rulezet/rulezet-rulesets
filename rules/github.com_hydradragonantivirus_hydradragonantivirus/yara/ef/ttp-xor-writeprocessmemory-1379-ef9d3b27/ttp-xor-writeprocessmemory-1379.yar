rule TTP_XOR_WriteProcessMemory_1379 {
  strings:
    $key_1379 = { 44 0b [2] 76 29 [2] 70 1c [2] 5e 1c [2] 61 00 }

  condition:
    any of them
}