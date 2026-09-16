rule TTP_XOR_WriteProcessMemory_5e45 {
  strings:
    $key_5e45 = { 09 37 [2] 3b 15 [2] 3d 20 [2] 13 20 [2] 2c 3c }

  condition:
    any of them
}