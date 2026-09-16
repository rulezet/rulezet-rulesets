rule TTP_XOR_WriteProcessMemory_5b78 {
  strings:
    $key_5b78 = { 0c 0a [2] 3e 28 [2] 38 1d [2] 16 1d [2] 29 01 }

  condition:
    any of them
}