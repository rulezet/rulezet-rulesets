rule TTP_XOR_WriteProcessMemory_79cc {
  strings:
    $key_79cc = { 2e be [2] 1c 9c [2] 1a a9 [2] 34 a9 [2] 0b b5 }

  condition:
    any of them
}