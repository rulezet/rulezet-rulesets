rule TTP_XOR_WriteProcessMemory_972b {
  strings:
    $key_972b = { c0 59 [2] f2 7b [2] f4 4e [2] da 4e [2] e5 52 }

  condition:
    any of them
}