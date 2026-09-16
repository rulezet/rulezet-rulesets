rule TTP_XOR_WriteProcessMemory_5e07 {
  strings:
    $key_5e07 = { 09 75 [2] 3b 57 [2] 3d 62 [2] 13 62 [2] 2c 7e }

  condition:
    any of them
}