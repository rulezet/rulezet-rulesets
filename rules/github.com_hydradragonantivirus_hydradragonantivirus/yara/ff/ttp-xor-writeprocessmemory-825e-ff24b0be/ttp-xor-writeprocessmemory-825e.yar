rule TTP_XOR_WriteProcessMemory_825e {
  strings:
    $key_825e = { d5 2c [2] e7 0e [2] e1 3b [2] cf 3b [2] f0 27 }

  condition:
    any of them
}