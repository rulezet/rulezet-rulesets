rule TTP_XOR_WriteProcessMemory_4468 {
  strings:
    $key_4468 = { 13 1a [2] 21 38 [2] 27 0d [2] 09 0d [2] 36 11 }

  condition:
    any of them
}