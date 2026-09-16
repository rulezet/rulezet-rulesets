rule TTP_XOR_WriteProcessMemory_903b {
  strings:
    $key_903b = { c7 49 [2] f5 6b [2] f3 5e [2] dd 5e [2] e2 42 }

  condition:
    any of them
}