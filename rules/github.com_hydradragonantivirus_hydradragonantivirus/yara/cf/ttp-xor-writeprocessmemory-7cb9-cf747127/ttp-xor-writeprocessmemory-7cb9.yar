rule TTP_XOR_WriteProcessMemory_7cb9 {
  strings:
    $key_7cb9 = { 2b cb [2] 19 e9 [2] 1f dc [2] 31 dc [2] 0e c0 }

  condition:
    any of them
}