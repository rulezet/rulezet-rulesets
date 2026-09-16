rule TTP_XOR_WriteProcessMemory_973a {
  strings:
    $key_973a = { c0 48 [2] f2 6a [2] f4 5f [2] da 5f [2] e5 43 }

  condition:
    any of them
}