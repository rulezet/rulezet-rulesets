rule TTP_XOR_WriteProcessMemory_83ee {
  strings:
    $key_83ee = { d4 9c [2] e6 be [2] e0 8b [2] ce 8b [2] f1 97 }

  condition:
    any of them
}