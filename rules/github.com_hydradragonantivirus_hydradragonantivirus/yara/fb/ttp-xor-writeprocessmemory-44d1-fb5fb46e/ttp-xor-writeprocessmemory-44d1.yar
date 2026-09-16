rule TTP_XOR_WriteProcessMemory_44d1 {
  strings:
    $key_44d1 = { 13 a3 [2] 21 81 [2] 27 b4 [2] 09 b4 [2] 36 a8 }

  condition:
    any of them
}