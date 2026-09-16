rule TTP_XOR_WriteProcessMemory_4fe0 {
  strings:
    $key_4fe0 = { 18 92 [2] 2a b0 [2] 2c 85 [2] 02 85 [2] 3d 99 }

  condition:
    any of them
}