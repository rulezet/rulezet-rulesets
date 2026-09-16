rule TTP_XOR_WriteProcessMemory_3b48 {
  strings:
    $key_3b48 = { 6c 3a [2] 5e 18 [2] 58 2d [2] 76 2d [2] 49 31 }

  condition:
    any of them
}