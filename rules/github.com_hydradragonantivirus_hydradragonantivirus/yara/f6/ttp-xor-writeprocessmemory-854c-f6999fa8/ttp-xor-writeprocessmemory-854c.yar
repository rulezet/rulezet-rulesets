rule TTP_XOR_WriteProcessMemory_854c {
  strings:
    $key_854c = { d2 3e [2] e0 1c [2] e6 29 [2] c8 29 [2] f7 35 }

  condition:
    any of them
}