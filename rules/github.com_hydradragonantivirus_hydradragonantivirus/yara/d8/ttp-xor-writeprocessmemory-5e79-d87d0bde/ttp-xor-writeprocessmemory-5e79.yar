rule TTP_XOR_WriteProcessMemory_5e79 {
  strings:
    $key_5e79 = { 09 0b [2] 3b 29 [2] 3d 1c [2] 13 1c [2] 2c 00 }

  condition:
    any of them
}