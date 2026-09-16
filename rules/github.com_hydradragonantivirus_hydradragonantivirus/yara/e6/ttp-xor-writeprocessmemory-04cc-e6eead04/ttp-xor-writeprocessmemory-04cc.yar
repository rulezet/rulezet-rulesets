rule TTP_XOR_WriteProcessMemory_04cc {
  strings:
    $key_04cc = { 53 be [2] 61 9c [2] 67 a9 [2] 49 a9 [2] 76 b5 }

  condition:
    any of them
}