rule TTP_XOR_WriteProcessMemory_875c {
  strings:
    $key_875c = { d0 2e [2] e2 0c [2] e4 39 [2] ca 39 [2] f5 25 }

  condition:
    any of them
}