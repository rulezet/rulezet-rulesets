rule TTP_XOR_WriteProcessMemory_93f9 {
  strings:
    $key_93f9 = { c4 8b [2] f6 a9 [2] f0 9c [2] de 9c [2] e1 80 }

  condition:
    any of them
}