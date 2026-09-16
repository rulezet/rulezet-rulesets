rule TTP_XOR_WriteProcessMemory_5e77 {
  strings:
    $key_5e77 = { 09 05 [2] 3b 27 [2] 3d 12 [2] 13 12 [2] 2c 0e }

  condition:
    any of them
}