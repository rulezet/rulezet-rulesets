rule TTP_XOR_WriteProcessMemory_86cc {
  strings:
    $key_86cc = { d1 be [2] e3 9c [2] e5 a9 [2] cb a9 [2] f4 b5 }

  condition:
    any of them
}