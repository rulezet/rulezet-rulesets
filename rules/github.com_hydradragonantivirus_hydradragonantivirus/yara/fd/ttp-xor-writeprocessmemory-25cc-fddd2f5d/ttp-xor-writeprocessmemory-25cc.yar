rule TTP_XOR_WriteProcessMemory_25cc {
  strings:
    $key_25cc = { 72 be [2] 40 9c [2] 46 a9 [2] 68 a9 [2] 57 b5 }

  condition:
    any of them
}