rule TTP_XOR_WriteProcessMemory_924c {
  strings:
    $key_924c = { c5 3e [2] f7 1c [2] f1 29 [2] df 29 [2] e0 35 }

  condition:
    any of them
}