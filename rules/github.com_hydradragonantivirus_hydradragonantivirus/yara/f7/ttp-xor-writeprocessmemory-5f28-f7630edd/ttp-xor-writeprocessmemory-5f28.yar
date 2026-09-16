rule TTP_XOR_WriteProcessMemory_5f28 {
  strings:
    $key_5f28 = { 08 5a [2] 3a 78 [2] 3c 4d [2] 12 4d [2] 2d 51 }

  condition:
    any of them
}