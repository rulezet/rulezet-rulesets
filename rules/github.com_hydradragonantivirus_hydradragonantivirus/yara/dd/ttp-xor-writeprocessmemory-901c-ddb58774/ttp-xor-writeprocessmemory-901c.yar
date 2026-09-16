rule TTP_XOR_WriteProcessMemory_901c {
  strings:
    $key_901c = { c7 6e [2] f5 4c [2] f3 79 [2] dd 79 [2] e2 65 }

  condition:
    any of them
}