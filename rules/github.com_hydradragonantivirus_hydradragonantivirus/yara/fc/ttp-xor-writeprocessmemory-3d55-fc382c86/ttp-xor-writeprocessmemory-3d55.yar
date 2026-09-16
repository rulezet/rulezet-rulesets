rule TTP_XOR_WriteProcessMemory_3d55 {
  strings:
    $key_3d55 = { 6a 27 [2] 58 05 [2] 5e 30 [2] 70 30 [2] 4f 2c }

  condition:
    any of them
}