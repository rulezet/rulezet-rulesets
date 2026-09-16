rule TTP_XOR_WriteProcessMemory_c7cc {
  strings:
    $key_c7cc = { 90 be [2] a2 9c [2] a4 a9 [2] 8a a9 [2] b5 b5 }

  condition:
    any of them
}