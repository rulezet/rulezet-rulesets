rule TTP_XOR_WriteProcessMemory_4e78 {
  strings:
    $key_4e78 = { 19 0a [2] 2b 28 [2] 2d 1d [2] 03 1d [2] 3c 01 }

  condition:
    any of them
}