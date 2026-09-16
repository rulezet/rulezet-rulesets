rule TTP_XOR_WriteProcessMemory_5948 {
  strings:
    $key_5948 = { 0e 3a [2] 3c 18 [2] 3a 2d [2] 14 2d [2] 2b 31 }

  condition:
    any of them
}