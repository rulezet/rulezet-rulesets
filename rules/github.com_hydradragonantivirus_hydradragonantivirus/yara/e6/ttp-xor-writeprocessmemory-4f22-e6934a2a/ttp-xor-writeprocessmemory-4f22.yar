rule TTP_XOR_WriteProcessMemory_4f22 {
  strings:
    $key_4f22 = { 18 50 [2] 2a 72 [2] 2c 47 [2] 02 47 [2] 3d 5b }

  condition:
    any of them
}