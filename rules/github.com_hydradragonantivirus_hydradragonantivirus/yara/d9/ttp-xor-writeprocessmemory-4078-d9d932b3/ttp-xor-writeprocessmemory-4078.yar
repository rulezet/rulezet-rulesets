rule TTP_XOR_WriteProcessMemory_4078 {
  strings:
    $key_4078 = { 17 0a [2] 25 28 [2] 23 1d [2] 0d 1d [2] 32 01 }

  condition:
    any of them
}