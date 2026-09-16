rule TTP_XOR_WriteProcessMemory_37d1 {
  strings:
    $key_37d1 = { 60 a3 [2] 52 81 [2] 54 b4 [2] 7a b4 [2] 45 a8 }

  condition:
    any of them
}