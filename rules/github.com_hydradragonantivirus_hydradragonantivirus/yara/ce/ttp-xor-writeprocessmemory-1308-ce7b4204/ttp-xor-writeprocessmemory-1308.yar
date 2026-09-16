rule TTP_XOR_WriteProcessMemory_1308 {
  strings:
    $key_1308 = { 44 7a [2] 76 58 [2] 70 6d [2] 5e 6d [2] 61 71 }

  condition:
    any of them
}