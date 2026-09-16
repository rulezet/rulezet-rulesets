rule TTP_XOR_WriteProcessMemory_934a {
  strings:
    $key_934a = { c4 38 [2] f6 1a [2] f0 2f [2] de 2f [2] e1 33 }

  condition:
    any of them
}