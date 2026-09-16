rule TTP_XOR_WriteProcessMemory_952a {
  strings:
    $key_952a = { c2 58 [2] f0 7a [2] f6 4f [2] d8 4f [2] e7 53 }

  condition:
    any of them
}