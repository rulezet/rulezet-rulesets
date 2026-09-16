rule TTP_XOR_WriteProcessMemory_6985 {
  strings:
    $key_6985 = { 3e f7 [2] 0c d5 [2] 0a e0 [2] 24 e0 [2] 1b fc }

  condition:
    any of them
}