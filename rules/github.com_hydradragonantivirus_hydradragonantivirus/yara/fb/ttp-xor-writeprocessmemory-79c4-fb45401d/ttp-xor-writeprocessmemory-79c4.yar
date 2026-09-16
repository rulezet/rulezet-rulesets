rule TTP_XOR_WriteProcessMemory_79c4 {
  strings:
    $key_79c4 = { 2e b6 [2] 1c 94 [2] 1a a1 [2] 34 a1 [2] 0b bd }

  condition:
    any of them
}