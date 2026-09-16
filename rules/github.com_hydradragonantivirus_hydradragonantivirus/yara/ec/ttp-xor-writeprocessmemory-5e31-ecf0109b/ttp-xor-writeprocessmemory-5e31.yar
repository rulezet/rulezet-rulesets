rule TTP_XOR_WriteProcessMemory_5e31 {
  strings:
    $key_5e31 = { 09 43 [2] 3b 61 [2] 3d 54 [2] 13 54 [2] 2c 48 }

  condition:
    any of them
}