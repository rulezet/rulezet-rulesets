rule TTP_XOR_WriteProcessMemory_6ff8 {
  strings:
    $key_6ff8 = { 38 8a [2] 0a a8 [2] 0c 9d [2] 22 9d [2] 1d 81 }

  condition:
    any of them
}