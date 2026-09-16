rule TTP_XOR_WriteProcessMemory_4cb9 {
  strings:
    $key_4cb9 = { 1b cb [2] 29 e9 [2] 2f dc [2] 01 dc [2] 3e c0 }

  condition:
    any of them
}