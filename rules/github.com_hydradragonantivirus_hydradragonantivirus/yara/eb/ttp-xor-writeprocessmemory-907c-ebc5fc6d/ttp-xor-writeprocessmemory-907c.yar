rule TTP_XOR_WriteProcessMemory_907c {
  strings:
    $key_907c = { c7 0e [2] f5 2c [2] f3 19 [2] dd 19 [2] e2 05 }

  condition:
    any of them
}