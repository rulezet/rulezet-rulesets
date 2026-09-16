rule TTP_XOR_WriteProcessMemory_974a {
  strings:
    $key_974a = { c0 38 [2] f2 1a [2] f4 2f [2] da 2f [2] e5 33 }

  condition:
    any of them
}