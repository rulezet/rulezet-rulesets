rule TTP_XOR_WriteProcessMemory_03d1 {
  strings:
    $key_03d1 = { 54 a3 [2] 66 81 [2] 60 b4 [2] 4e b4 [2] 71 a8 }

  condition:
    any of them
}