rule TTP_XOR_WriteProcessMemory_97a8 {
  strings:
    $key_97a8 = { c0 da [2] f2 f8 [2] f4 cd [2] da cd [2] e5 d1 }

  condition:
    any of them
}