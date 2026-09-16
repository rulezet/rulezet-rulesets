rule TTP_XOR_WriteProcessMemory_70f3 {
  strings:
    $key_70f3 = { 27 81 [2] 15 a3 [2] 13 96 [2] 3d 96 [2] 02 8a }

  condition:
    any of them
}