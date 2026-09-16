rule TTP_XOR_WriteProcessMemory_77cc {
  strings:
    $key_77cc = { 20 be [2] 12 9c [2] 14 a9 [2] 3a a9 [2] 05 b5 }

  condition:
    any of them
}