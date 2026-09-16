rule TTP_XOR_WriteProcessMemory_72cc {
  strings:
    $key_72cc = { 25 be [2] 17 9c [2] 11 a9 [2] 3f a9 [2] 00 b5 }

  condition:
    any of them
}