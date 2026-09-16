rule TTP_XOR_WriteProcessMemory_837e {
  strings:
    $key_837e = { d4 0c [2] e6 2e [2] e0 1b [2] ce 1b [2] f1 07 }

  condition:
    any of them
}