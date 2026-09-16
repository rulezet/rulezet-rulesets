rule TTP_XOR_WriteProcessMemory_0ff8 {
  strings:
    $key_0ff8 = { 58 8a [2] 6a a8 [2] 6c 9d [2] 42 9d [2] 7d 81 }

  condition:
    any of them
}