rule TTP_XOR_WriteProcessMemory_69c4 {
  strings:
    $key_69c4 = { 3e b6 [2] 0c 94 [2] 0a a1 [2] 24 a1 [2] 1b bd }

  condition:
    any of them
}