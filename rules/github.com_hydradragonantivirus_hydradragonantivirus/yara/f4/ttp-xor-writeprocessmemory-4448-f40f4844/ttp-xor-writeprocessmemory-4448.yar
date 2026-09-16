rule TTP_XOR_WriteProcessMemory_4448 {
  strings:
    $key_4448 = { 13 3a [2] 21 18 [2] 27 2d [2] 09 2d [2] 36 31 }

  condition:
    any of them
}