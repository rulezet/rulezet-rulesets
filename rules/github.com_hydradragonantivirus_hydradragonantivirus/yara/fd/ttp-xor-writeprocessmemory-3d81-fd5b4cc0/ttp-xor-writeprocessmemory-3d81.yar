rule TTP_XOR_WriteProcessMemory_3d81 {
  strings:
    $key_3d81 = { 6a f3 [2] 58 d1 [2] 5e e4 [2] 70 e4 [2] 4f f8 }

  condition:
    any of them
}