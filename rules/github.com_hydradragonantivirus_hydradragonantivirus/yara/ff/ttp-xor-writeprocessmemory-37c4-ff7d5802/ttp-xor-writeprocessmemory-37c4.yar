rule TTP_XOR_WriteProcessMemory_37c4 {
  strings:
    $key_37c4 = { 60 b6 [2] 52 94 [2] 54 a1 [2] 7a a1 [2] 45 bd }

  condition:
    any of them
}