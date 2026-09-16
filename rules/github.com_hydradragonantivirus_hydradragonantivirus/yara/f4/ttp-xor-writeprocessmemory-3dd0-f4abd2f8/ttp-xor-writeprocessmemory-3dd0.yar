rule TTP_XOR_WriteProcessMemory_3dd0 {
  strings:
    $key_3dd0 = { 6a a2 [2] 58 80 [2] 5e b5 [2] 70 b5 [2] 4f a9 }

  condition:
    any of them
}