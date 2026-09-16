rule TTP_XOR_WriteProcessMemory_1397 {
  strings:
    $key_1397 = { 44 e5 [2] 76 c7 [2] 70 f2 [2] 5e f2 [2] 61 ee }

  condition:
    any of them
}