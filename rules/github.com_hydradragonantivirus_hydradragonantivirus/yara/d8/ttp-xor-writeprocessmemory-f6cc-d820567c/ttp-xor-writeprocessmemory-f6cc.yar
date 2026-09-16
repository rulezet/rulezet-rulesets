rule TTP_XOR_WriteProcessMemory_f6cc {
  strings:
    $key_f6cc = { a1 be [2] 93 9c [2] 95 a9 [2] bb a9 [2] 84 b5 }

  condition:
    any of them
}