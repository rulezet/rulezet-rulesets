rule TTP_XOR_WriteProcessMemory_936e {
  strings:
    $key_936e = { c4 1c [2] f6 3e [2] f0 0b [2] de 0b [2] e1 17 }

  condition:
    any of them
}