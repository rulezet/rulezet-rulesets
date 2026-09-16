rule TTP_XOR_WriteProcessMemory_6448 {
  strings:
    $key_6448 = { 33 3a [2] 01 18 [2] 07 2d [2] 29 2d [2] 16 31 }

  condition:
    any of them
}