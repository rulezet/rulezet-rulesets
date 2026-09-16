rule TTP_XOR_WriteProcessMemory_957c {
  strings:
    $key_957c = { c2 0e [2] f0 2c [2] f6 19 [2] d8 19 [2] e7 05 }

  condition:
    any of them
}