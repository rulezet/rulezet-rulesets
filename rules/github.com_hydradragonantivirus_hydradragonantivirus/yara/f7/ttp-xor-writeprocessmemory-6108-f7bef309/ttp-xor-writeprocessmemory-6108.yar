rule TTP_XOR_WriteProcessMemory_6108 {
  strings:
    $key_6108 = { 36 7a [2] 04 58 [2] 02 6d [2] 2c 6d [2] 13 71 }

  condition:
    any of them
}