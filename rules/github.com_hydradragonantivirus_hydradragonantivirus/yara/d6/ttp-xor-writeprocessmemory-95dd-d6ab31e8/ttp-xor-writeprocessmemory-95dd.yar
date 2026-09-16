rule TTP_XOR_WriteProcessMemory_95dd {
  strings:
    $key_95dd = { c2 af [2] f0 8d [2] f6 b8 [2] d8 b8 [2] e7 a4 }

  condition:
    any of them
}