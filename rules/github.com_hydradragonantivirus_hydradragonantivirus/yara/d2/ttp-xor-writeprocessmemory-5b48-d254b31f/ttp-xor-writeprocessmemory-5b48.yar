rule TTP_XOR_WriteProcessMemory_5b48 {
  strings:
    $key_5b48 = { 0c 3a [2] 3e 18 [2] 38 2d [2] 16 2d [2] 29 31 }

  condition:
    any of them
}