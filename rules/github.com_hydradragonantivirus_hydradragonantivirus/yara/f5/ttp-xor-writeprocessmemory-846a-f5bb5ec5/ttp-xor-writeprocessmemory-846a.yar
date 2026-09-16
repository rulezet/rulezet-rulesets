rule TTP_XOR_WriteProcessMemory_846a {
  strings:
    $key_846a = { d3 18 [2] e1 3a [2] e7 0f [2] c9 0f [2] f6 13 }

  condition:
    any of them
}