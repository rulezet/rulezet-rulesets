rule TTP_XOR_WriteProcessMemory_5e40 {
  strings:
    $key_5e40 = { 09 32 [2] 3b 10 [2] 3d 25 [2] 13 25 [2] 2c 39 }

  condition:
    any of them
}