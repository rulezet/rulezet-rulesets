rule TTP_XOR_WriteProcessMemory_e3cc {
  strings:
    $key_e3cc = { b4 be [2] 86 9c [2] 80 a9 [2] ae a9 [2] 91 b5 }

  condition:
    any of them
}