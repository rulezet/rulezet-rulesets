rule TTP_XOR_WriteProcessMemory_3cb9 {
  strings:
    $key_3cb9 = { 6b cb [2] 59 e9 [2] 5f dc [2] 71 dc [2] 4e c0 }

  condition:
    any of them
}