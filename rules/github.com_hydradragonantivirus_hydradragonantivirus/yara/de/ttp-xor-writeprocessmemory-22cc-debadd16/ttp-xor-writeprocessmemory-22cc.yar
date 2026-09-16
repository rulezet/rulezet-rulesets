rule TTP_XOR_WriteProcessMemory_22cc {
  strings:
    $key_22cc = { 75 be [2] 47 9c [2] 41 a9 [2] 6f a9 [2] 50 b5 }

  condition:
    any of them
}