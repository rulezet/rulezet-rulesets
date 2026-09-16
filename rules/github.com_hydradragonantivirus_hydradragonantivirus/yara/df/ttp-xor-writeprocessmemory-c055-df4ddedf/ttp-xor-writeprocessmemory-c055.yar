rule TTP_XOR_WriteProcessMemory_c055 {
  strings:
    $key_c055 = { 97 27 [2] a5 05 [2] a3 30 [2] 8d 30 [2] b2 2c }

  condition:
    any of them
}