rule TTP_XOR_WriteProcessMemory_5e53 {
  strings:
    $key_5e53 = { 09 21 [2] 3b 03 [2] 3d 36 [2] 13 36 [2] 2c 2a }

  condition:
    any of them
}