rule TTP_XOR_WriteProcessMemory_4708 {
  strings:
    $key_4708 = { 10 7a [2] 22 58 [2] 24 6d [2] 0a 6d [2] 35 71 }

  condition:
    any of them
}