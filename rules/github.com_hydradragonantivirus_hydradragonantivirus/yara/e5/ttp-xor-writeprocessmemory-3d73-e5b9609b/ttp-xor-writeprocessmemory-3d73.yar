rule TTP_XOR_WriteProcessMemory_3d73 {
  strings:
    $key_3d73 = { 6a 01 [2] 58 23 [2] 5e 16 [2] 70 16 [2] 4f 0a }

  condition:
    any of them
}