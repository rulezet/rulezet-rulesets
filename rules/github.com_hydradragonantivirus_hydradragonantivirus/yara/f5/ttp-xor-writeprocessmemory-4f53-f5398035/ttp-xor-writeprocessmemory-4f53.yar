rule TTP_XOR_WriteProcessMemory_4f53 {
  strings:
    $key_4f53 = { 18 21 [2] 2a 03 [2] 2c 36 [2] 02 36 [2] 3d 2a }

  condition:
    any of them
}