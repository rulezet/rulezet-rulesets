rule TTP_XOR_WriteProcessMemory_1368 {
  strings:
    $key_1368 = { 44 1a [2] 76 38 [2] 70 0d [2] 5e 0d [2] 61 11 }

  condition:
    any of them
}