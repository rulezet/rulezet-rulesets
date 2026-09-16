rule TTP_XOR_WriteProcessMemory_935c {
  strings:
    $key_935c = { c4 2e [2] f6 0c [2] f0 39 [2] de 39 [2] e1 25 }

  condition:
    any of them
}