rule TTP_XOR_WriteProcessMemory_02d0 {
  strings:
    $key_02d0 = { 55 a2 [2] 67 80 [2] 61 b5 [2] 4f b5 [2] 70 a9 }

  condition:
    any of them
}