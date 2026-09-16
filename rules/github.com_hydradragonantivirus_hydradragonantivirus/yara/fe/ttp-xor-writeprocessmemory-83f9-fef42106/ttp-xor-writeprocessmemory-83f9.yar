rule TTP_XOR_WriteProcessMemory_83f9 {
  strings:
    $key_83f9 = { d4 8b [2] e6 a9 [2] e0 9c [2] ce 9c [2] f1 80 }

  condition:
    any of them
}