rule TTP_XOR_WriteProcessMemory_1ac4 {
  strings:
    $key_1ac4 = { 4d b6 [2] 7f 94 [2] 79 a1 [2] 57 a1 [2] 68 bd }

  condition:
    any of them
}