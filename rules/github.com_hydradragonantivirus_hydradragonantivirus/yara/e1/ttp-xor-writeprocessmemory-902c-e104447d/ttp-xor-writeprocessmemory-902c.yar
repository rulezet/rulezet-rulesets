rule TTP_XOR_WriteProcessMemory_902c {
  strings:
    $key_902c = { c7 5e [2] f5 7c [2] f3 49 [2] dd 49 [2] e2 55 }

  condition:
    any of them
}