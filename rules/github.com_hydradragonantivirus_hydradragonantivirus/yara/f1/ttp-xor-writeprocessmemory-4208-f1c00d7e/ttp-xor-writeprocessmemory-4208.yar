rule TTP_XOR_WriteProcessMemory_4208 {
  strings:
    $key_4208 = { 15 7a [2] 27 58 [2] 21 6d [2] 0f 6d [2] 30 71 }

  condition:
    any of them
}