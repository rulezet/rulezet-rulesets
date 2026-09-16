rule TTP_XOR_WriteProcessMemory_37d0 {
  strings:
    $key_37d0 = { 60 a2 [2] 52 80 [2] 54 b5 [2] 7a b5 [2] 45 a9 }

  condition:
    any of them
}