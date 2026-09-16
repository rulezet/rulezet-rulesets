rule TTP_XOR_WriteProcessMemory_5c78 {
  strings:
    $key_5c78 = { 0b 0a [2] 39 28 [2] 3f 1d [2] 11 1d [2] 2e 01 }

  condition:
    any of them
}