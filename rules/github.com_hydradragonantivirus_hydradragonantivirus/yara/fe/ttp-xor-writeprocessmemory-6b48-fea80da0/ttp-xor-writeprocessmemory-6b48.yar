rule TTP_XOR_WriteProcessMemory_6b48 {
  strings:
    $key_6b48 = { 3c 3a [2] 0e 18 [2] 08 2d [2] 26 2d [2] 19 31 }

  condition:
    any of them
}