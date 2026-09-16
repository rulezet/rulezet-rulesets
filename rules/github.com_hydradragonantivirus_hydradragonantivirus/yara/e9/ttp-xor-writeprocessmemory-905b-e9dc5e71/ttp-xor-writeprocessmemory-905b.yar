rule TTP_XOR_WriteProcessMemory_905b {
  strings:
    $key_905b = { c7 29 [2] f5 0b [2] f3 3e [2] dd 3e [2] e2 22 }

  condition:
    any of them
}