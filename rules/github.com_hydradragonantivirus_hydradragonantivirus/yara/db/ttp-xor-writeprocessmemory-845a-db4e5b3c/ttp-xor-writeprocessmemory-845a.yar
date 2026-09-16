rule TTP_XOR_WriteProcessMemory_845a {
  strings:
    $key_845a = { d3 28 [2] e1 0a [2] e7 3f [2] c9 3f [2] f6 23 }

  condition:
    any of them
}