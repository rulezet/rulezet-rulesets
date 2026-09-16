rule TTP_XOR_WriteProcessMemory_827b {
  strings:
    $key_827b = { d5 09 [2] e7 2b [2] e1 1e [2] cf 1e [2] f0 02 }

  condition:
    any of them
}