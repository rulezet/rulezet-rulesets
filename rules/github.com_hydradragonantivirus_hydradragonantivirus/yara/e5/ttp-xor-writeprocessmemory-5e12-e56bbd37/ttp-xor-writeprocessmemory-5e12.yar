rule TTP_XOR_WriteProcessMemory_5e12 {
  strings:
    $key_5e12 = { 09 60 [2] 3b 42 [2] 3d 77 [2] 13 77 [2] 2c 6b }

  condition:
    any of them
}