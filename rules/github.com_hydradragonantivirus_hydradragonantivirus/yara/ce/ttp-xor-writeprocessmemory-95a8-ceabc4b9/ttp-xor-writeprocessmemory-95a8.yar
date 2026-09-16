rule TTP_XOR_WriteProcessMemory_95a8 {
  strings:
    $key_95a8 = { c2 da [2] f0 f8 [2] f6 cd [2] d8 cd [2] e7 d1 }

  condition:
    any of them
}