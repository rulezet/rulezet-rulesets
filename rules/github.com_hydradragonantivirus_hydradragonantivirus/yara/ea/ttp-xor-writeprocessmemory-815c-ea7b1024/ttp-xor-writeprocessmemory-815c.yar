rule TTP_XOR_WriteProcessMemory_815c {
  strings:
    $key_815c = { d6 2e [2] e4 0c [2] e2 39 [2] cc 39 [2] f3 25 }

  condition:
    any of them
}