rule TTP_XOR_WriteProcessMemory_1342 {
  strings:
    $key_1342 = { 44 30 [2] 76 12 [2] 70 27 [2] 5e 27 [2] 61 3b }

  condition:
    any of them
}