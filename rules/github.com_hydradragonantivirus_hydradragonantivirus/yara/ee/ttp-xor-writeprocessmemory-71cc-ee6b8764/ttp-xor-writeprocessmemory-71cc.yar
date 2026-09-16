rule TTP_XOR_WriteProcessMemory_71cc {
  strings:
    $key_71cc = { 26 be [2] 14 9c [2] 12 a9 [2] 3c a9 [2] 03 b5 }

  condition:
    any of them
}