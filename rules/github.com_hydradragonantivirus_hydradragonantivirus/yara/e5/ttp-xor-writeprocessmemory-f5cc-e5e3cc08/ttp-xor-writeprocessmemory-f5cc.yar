rule TTP_XOR_WriteProcessMemory_f5cc {
  strings:
    $key_f5cc = { a2 be [2] 90 9c [2] 96 a9 [2] b8 a9 [2] 87 b5 }

  condition:
    any of them
}