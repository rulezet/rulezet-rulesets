rule TTP_XOR_WriteProcessMemory_5d78 {
  strings:
    $key_5d78 = { 0a 0a [2] 38 28 [2] 3e 1d [2] 10 1d [2] 2f 01 }

  condition:
    any of them
}