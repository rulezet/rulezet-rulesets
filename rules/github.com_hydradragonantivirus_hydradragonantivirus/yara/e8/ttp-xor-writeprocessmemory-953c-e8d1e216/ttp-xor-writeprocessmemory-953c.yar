rule TTP_XOR_WriteProcessMemory_953c {
  strings:
    $key_953c = { c2 4e [2] f0 6c [2] f6 59 [2] d8 59 [2] e7 45 }

  condition:
    any of them
}