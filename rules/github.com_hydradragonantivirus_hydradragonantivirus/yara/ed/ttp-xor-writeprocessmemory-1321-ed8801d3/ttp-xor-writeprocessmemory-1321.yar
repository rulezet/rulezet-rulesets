rule TTP_XOR_WriteProcessMemory_1321 {
  strings:
    $key_1321 = { 44 53 [2] 76 71 [2] 70 44 [2] 5e 44 [2] 61 58 }

  condition:
    any of them
}