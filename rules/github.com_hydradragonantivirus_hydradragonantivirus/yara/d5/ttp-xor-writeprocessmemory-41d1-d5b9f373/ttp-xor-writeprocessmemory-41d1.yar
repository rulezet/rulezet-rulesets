rule TTP_XOR_WriteProcessMemory_41d1 {
  strings:
    $key_41d1 = { 16 a3 [2] 24 81 [2] 22 b4 [2] 0c b4 [2] 33 a8 }

  condition:
    any of them
}