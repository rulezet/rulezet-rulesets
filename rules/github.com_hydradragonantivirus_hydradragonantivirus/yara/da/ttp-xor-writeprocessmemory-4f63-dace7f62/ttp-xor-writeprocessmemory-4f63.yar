rule TTP_XOR_WriteProcessMemory_4f63 {
  strings:
    $key_4f63 = { 18 11 [2] 2a 33 [2] 2c 06 [2] 02 06 [2] 3d 1a }

  condition:
    any of them
}