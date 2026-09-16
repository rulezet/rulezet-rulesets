rule TTP_XOR_WriteProcessMemory_81fd {
  strings:
    $key_81fd = { d6 8f [2] e4 ad [2] e2 98 [2] cc 98 [2] f3 84 }

  condition:
    any of them
}