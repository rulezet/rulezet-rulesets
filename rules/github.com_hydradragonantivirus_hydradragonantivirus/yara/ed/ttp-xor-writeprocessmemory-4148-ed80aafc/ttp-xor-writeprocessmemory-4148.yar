rule TTP_XOR_WriteProcessMemory_4148 {
  strings:
    $key_4148 = { 16 3a [2] 24 18 [2] 22 2d [2] 0c 2d [2] 33 31 }

  condition:
    any of them
}