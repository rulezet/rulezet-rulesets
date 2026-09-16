rule TTP_XOR_WriteProcessMemory_4f12 {
  strings:
    $key_4f12 = { 18 60 [2] 2a 42 [2] 2c 77 [2] 02 77 [2] 3d 6b }

  condition:
    any of them
}