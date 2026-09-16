rule TTP_XOR_WriteProcessMemory_813a {
  strings:
    $key_813a = { d6 48 [2] e4 6a [2] e2 5f [2] cc 5f [2] f3 43 }

  condition:
    any of them
}