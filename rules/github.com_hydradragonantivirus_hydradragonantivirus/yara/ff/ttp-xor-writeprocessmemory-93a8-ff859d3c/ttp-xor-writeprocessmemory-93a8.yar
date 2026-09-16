rule TTP_XOR_WriteProcessMemory_93a8 {
  strings:
    $key_93a8 = { c4 da [2] f6 f8 [2] f0 cd [2] de cd [2] e1 d1 }

  condition:
    any of them
}