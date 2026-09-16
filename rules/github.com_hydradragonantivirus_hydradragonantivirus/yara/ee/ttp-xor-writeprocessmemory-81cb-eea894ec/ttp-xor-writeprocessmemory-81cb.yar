rule TTP_XOR_WriteProcessMemory_81cb {
  strings:
    $key_81cb = { d6 b9 [2] e4 9b [2] e2 ae [2] cc ae [2] f3 b2 }

  condition:
    any of them
}