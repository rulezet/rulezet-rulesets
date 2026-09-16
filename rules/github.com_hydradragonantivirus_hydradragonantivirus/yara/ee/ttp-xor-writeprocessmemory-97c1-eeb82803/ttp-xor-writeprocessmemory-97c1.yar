rule TTP_XOR_WriteProcessMemory_97c1 {
  strings:
    $key_97c1 = { c0 b3 [2] f2 91 [2] f4 a4 [2] da a4 [2] e5 b8 }

  condition:
    any of them
}