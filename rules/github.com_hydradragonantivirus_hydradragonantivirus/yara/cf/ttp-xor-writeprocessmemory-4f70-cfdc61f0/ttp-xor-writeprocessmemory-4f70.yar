rule TTP_XOR_WriteProcessMemory_4f70 {
  strings:
    $key_4f70 = { 18 02 [2] 2a 20 [2] 2c 15 [2] 02 15 [2] 3d 09 }

  condition:
    any of them
}