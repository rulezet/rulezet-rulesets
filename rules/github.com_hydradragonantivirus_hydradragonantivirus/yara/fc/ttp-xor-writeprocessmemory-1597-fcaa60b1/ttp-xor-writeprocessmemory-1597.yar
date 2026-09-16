rule TTP_XOR_WriteProcessMemory_1597 {
  strings:
    $key_1597 = { 42 e5 [2] 70 c7 [2] 76 f2 [2] 58 f2 [2] 67 ee }

  condition:
    any of them
}