rule TTP_XOR_WriteProcessMemory_5468 {
  strings:
    $key_5468 = { 03 1a [2] 31 38 [2] 37 0d [2] 19 0d [2] 26 11 }

  condition:
    any of them
}