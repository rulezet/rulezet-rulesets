rule TTP_XOR_WriteProcessMemory_5e11 {
  strings:
    $key_5e11 = { 09 63 [2] 3b 41 [2] 3d 74 [2] 13 74 [2] 2c 68 }

  condition:
    any of them
}