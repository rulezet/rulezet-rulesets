rule TTP_XOR_WriteProcessMemory_972d {
  strings:
    $key_972d = { c0 5f [2] f2 7d [2] f4 48 [2] da 48 [2] e5 54 }

  condition:
    any of them
}