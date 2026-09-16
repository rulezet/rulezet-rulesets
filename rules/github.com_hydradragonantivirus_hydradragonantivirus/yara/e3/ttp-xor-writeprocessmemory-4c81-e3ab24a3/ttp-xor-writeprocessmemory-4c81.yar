rule TTP_XOR_WriteProcessMemory_4c81 {
  strings:
    $key_4c81 = { 1b f3 [2] 29 d1 [2] 2f e4 [2] 01 e4 [2] 3e f8 }

  condition:
    any of them
}