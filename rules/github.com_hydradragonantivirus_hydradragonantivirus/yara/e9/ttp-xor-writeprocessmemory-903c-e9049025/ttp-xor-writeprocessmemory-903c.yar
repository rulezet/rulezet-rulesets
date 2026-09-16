rule TTP_XOR_WriteProcessMemory_903c {
  strings:
    $key_903c = { c7 4e [2] f5 6c [2] f3 59 [2] dd 59 [2] e2 45 }

  condition:
    any of them
}