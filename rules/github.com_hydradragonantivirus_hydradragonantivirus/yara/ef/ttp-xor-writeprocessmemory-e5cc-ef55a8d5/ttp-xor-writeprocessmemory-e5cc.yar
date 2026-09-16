rule TTP_XOR_WriteProcessMemory_e5cc {
  strings:
    $key_e5cc = { b2 be [2] 80 9c [2] 86 a9 [2] a8 a9 [2] 97 b5 }

  condition:
    any of them
}