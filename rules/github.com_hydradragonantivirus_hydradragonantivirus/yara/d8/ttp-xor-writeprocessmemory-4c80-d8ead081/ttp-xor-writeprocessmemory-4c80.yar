rule TTP_XOR_WriteProcessMemory_4c80 {
  strings:
    $key_4c80 = { 1b f2 [2] 29 d0 [2] 2f e5 [2] 01 e5 [2] 3e f9 }

  condition:
    any of them
}