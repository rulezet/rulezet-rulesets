rule TTP_XOR_WriteProcessMemory_1985 {
  strings:
    $key_1985 = { 4e f7 [2] 7c d5 [2] 7a e0 [2] 54 e0 [2] 6b fc }

  condition:
    any of them
}