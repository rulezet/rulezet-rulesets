rule TTP_XOR_WriteProcessMemory_0b08 {
  strings:
    $key_0b08 = { 5c 7a [2] 6e 58 [2] 68 6d [2] 46 6d [2] 79 71 }

  condition:
    any of them
}