rule TTP_XOR_WriteProcessMemory_81ea {
  strings:
    $key_81ea = { d6 98 [2] e4 ba [2] e2 8f [2] cc 8f [2] f3 93 }

  condition:
    any of them
}