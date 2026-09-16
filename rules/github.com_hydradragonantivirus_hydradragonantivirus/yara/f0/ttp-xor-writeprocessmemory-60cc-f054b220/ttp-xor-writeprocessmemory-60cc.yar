rule TTP_XOR_WriteProcessMemory_60cc {
  strings:
    $key_60cc = { 37 be [2] 05 9c [2] 03 a9 [2] 2d a9 [2] 12 b5 }

  condition:
    any of them
}