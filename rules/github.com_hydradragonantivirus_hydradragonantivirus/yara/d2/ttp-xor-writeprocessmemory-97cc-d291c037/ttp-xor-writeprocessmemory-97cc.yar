rule TTP_XOR_WriteProcessMemory_97cc {
  strings:
    $key_97cc = { c0 be [2] f2 9c [2] f4 a9 [2] da a9 [2] e5 b5 }

  condition:
    any of them
}