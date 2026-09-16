rule TTP_XOR_WriteProcessMemory_1348 {
  strings:
    $key_1348 = { 44 3a [2] 76 18 [2] 70 2d [2] 5e 2d [2] 61 31 }

  condition:
    any of them
}