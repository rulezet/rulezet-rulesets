rule TTP_XOR_WriteProcessMemory_0b78 {
  strings:
    $key_0b78 = { 5c 0a [2] 6e 28 [2] 68 1d [2] 46 1d [2] 79 01 }

  condition:
    any of them
}