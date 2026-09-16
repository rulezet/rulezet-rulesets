rule TTP_XOR_WriteProcessMemory_42cc {
  strings:
    $key_42cc = { 15 be [2] 27 9c [2] 21 a9 [2] 0f a9 [2] 30 b5 }

  condition:
    any of them
}