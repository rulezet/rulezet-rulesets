rule TTP_XOR_WriteProcessMemory_7f48 {
  strings:
    $key_7f48 = { 28 3a [2] 1a 18 [2] 1c 2d [2] 32 2d [2] 0d 31 }

  condition:
    any of them
}