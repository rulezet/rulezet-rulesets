rule TTP_XOR_WriteProcessMemory_947c {
  strings:
    $key_947c = { c3 0e [2] f1 2c [2] f7 19 [2] d9 19 [2] e6 05 }

  condition:
    any of them
}