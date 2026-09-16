rule TTP_XOR_WriteProcessMemory_d2cc {
  strings:
    $key_d2cc = { 85 be [2] b7 9c [2] b1 a9 [2] 9f a9 [2] a0 b5 }

  condition:
    any of them
}