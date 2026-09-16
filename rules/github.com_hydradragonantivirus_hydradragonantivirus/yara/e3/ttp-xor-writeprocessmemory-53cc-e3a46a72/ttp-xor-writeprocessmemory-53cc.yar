rule TTP_XOR_WriteProcessMemory_53cc {
  strings:
    $key_53cc = { 04 be [2] 36 9c [2] 30 a9 [2] 1e a9 [2] 21 b5 }

  condition:
    any of them
}