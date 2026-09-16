rule TTP_XOR_WriteProcessMemory_4f21 {
  strings:
    $key_4f21 = { 18 53 [2] 2a 71 [2] 2c 44 [2] 02 44 [2] 3d 58 }

  condition:
    any of them
}