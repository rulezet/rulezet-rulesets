rule TTP_XOR_WriteProcessMemory_6508 {
  strings:
    $key_6508 = { 32 7a [2] 00 58 [2] 06 6d [2] 28 6d [2] 17 71 }

  condition:
    any of them
}