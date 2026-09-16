rule TTP_XOR_WriteProcessMemory_a0cc {
  strings:
    $key_a0cc = { f7 be [2] c5 9c [2] c3 a9 [2] ed a9 [2] d2 b5 }

  condition:
    any of them
}