rule TTP_XOR_WriteProcessMemory_4268 {
  strings:
    $key_4268 = { 15 1a [2] 27 38 [2] 21 0d [2] 0f 0d [2] 30 11 }

  condition:
    any of them
}