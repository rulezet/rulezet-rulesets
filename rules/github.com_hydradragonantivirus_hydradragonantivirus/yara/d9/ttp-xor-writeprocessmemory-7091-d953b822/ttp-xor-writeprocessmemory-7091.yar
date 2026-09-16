rule TTP_XOR_WriteProcessMemory_7091 {
  strings:
    $key_7091 = { 27 e3 [2] 15 c1 [2] 13 f4 [2] 3d f4 [2] 02 e8 }

  condition:
    any of them
}