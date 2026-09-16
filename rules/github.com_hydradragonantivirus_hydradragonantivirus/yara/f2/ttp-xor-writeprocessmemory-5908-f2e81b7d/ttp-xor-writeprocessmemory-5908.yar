rule TTP_XOR_WriteProcessMemory_5908 {
  strings:
    $key_5908 = { 0e 7a [2] 3c 58 [2] 3a 6d [2] 14 6d [2] 2b 71 }

  condition:
    any of them
}