rule TTP_XOR_WriteProcessMemory_4f00 {
  strings:
    $key_4f00 = { 18 72 [2] 2a 50 [2] 2c 65 [2] 02 65 [2] 3d 79 }

  condition:
    any of them
}