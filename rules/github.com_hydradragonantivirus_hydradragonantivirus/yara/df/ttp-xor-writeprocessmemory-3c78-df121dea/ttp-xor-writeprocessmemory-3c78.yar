rule TTP_XOR_WriteProcessMemory_3c78 {
  strings:
    $key_3c78 = { 6b 0a [2] 59 28 [2] 5f 1d [2] 71 1d [2] 4e 01 }

  condition:
    any of them
}