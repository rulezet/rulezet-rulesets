rule TTP_XOR_WriteProcessMemory_54cc {
  strings:
    $key_54cc = { 03 be [2] 31 9c [2] 37 a9 [2] 19 a9 [2] 26 b5 }

  condition:
    any of them
}