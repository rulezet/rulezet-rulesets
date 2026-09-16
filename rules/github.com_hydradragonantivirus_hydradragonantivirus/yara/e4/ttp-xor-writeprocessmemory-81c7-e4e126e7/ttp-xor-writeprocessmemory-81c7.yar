rule TTP_XOR_WriteProcessMemory_81c7 {
  strings:
    $key_81c7 = { d6 b5 [2] e4 97 [2] e2 a2 [2] cc a2 [2] f3 be }

  condition:
    any of them
}