rule TTP_XOR_WriteProcessMemory_975c {
  strings:
    $key_975c = { c0 2e [2] f2 0c [2] f4 39 [2] da 39 [2] e5 25 }

  condition:
    any of them
}