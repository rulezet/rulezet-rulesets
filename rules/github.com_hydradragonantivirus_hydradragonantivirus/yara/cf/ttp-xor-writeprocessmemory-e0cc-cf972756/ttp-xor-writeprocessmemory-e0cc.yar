rule TTP_XOR_WriteProcessMemory_e0cc {
  strings:
    $key_e0cc = { b7 be [2] 85 9c [2] 83 a9 [2] ad a9 [2] 92 b5 }

  condition:
    any of them
}