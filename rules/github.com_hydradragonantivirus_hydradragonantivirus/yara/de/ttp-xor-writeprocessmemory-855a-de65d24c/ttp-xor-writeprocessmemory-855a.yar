rule TTP_XOR_WriteProcessMemory_855a {
  strings:
    $key_855a = { d2 28 [2] e0 0a [2] e6 3f [2] c8 3f [2] f7 23 }

  condition:
    any of them
}