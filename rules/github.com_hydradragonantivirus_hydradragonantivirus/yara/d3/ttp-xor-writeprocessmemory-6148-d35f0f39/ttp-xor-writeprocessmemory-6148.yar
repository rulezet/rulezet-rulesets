rule TTP_XOR_WriteProcessMemory_6148 {
  strings:
    $key_6148 = { 36 3a [2] 04 18 [2] 02 2d [2] 2c 2d [2] 13 31 }

  condition:
    any of them
}