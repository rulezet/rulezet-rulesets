rule TTP_XOR_WriteProcessMemory_4fa1 {
  strings:
    $key_4fa1 = { 18 d3 [2] 2a f1 [2] 2c c4 [2] 02 c4 [2] 3d d8 }

  condition:
    any of them
}