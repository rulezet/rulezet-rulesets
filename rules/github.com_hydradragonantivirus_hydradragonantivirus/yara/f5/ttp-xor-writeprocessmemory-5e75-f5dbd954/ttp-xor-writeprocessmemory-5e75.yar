rule TTP_XOR_WriteProcessMemory_5e75 {
  strings:
    $key_5e75 = { 09 07 [2] 3b 25 [2] 3d 10 [2] 13 10 [2] 2c 0c }

  condition:
    any of them
}