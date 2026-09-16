rule TTP_XOR_WriteProcessMemory_853c {
  strings:
    $key_853c = { d2 4e [2] e0 6c [2] e6 59 [2] c8 59 [2] f7 45 }

  condition:
    any of them
}