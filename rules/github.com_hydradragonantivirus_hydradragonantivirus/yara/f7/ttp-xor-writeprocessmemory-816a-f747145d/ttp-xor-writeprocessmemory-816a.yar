rule TTP_XOR_WriteProcessMemory_816a {
  strings:
    $key_816a = { d6 18 [2] e4 3a [2] e2 0f [2] cc 0f [2] f3 13 }

  condition:
    any of them
}