rule TTP_XOR_WriteProcessMemory_964c {
  strings:
    $key_964c = { c1 3e [2] f3 1c [2] f5 29 [2] db 29 [2] e4 35 }

  condition:
    any of them
}