rule TTP_XOR_WriteProcessMemory_3e48 {
  strings:
    $key_3e48 = { 69 3a [2] 5b 18 [2] 5d 2d [2] 73 2d [2] 4c 31 }

  condition:
    any of them
}