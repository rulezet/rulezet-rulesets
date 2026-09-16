rule TTP_XOR_WriteProcessMemory_837c {
  strings:
    $key_837c = { d4 0e [2] e6 2c [2] e0 19 [2] ce 19 [2] f1 05 }

  condition:
    any of them
}