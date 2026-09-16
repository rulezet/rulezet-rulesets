rule TTP_XOR_WriteProcessMemory_5e70 {
  strings:
    $key_5e70 = { 09 02 [2] 3b 20 [2] 3d 15 [2] 13 15 [2] 2c 09 }

  condition:
    any of them
}