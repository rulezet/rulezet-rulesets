rule TTP_XOR_WriteProcessMemory_37c0 {
  strings:
    $key_37c0 = { 60 b2 [2] 52 90 [2] 54 a5 [2] 7a a5 [2] 45 b9 }

  condition:
    any of them
}