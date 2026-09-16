rule TTP_XOR_WriteProcessMemory_4f08 {
  strings:
    $key_4f08 = { 18 7a [2] 2a 58 [2] 2c 6d [2] 02 6d [2] 3d 71 }

  condition:
    any of them
}