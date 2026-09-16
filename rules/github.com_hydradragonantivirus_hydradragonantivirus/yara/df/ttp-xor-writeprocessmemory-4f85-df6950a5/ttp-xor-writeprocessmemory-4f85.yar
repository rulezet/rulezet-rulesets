rule TTP_XOR_WriteProcessMemory_4f85 {
  strings:
    $key_4f85 = { 18 f7 [2] 2a d5 [2] 2c e0 [2] 02 e0 [2] 3d fc }

  condition:
    any of them
}