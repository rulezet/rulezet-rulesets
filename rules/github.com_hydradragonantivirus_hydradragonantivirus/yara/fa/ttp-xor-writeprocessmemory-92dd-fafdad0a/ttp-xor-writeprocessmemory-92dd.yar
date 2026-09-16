rule TTP_XOR_WriteProcessMemory_92dd {
  strings:
    $key_92dd = { c5 af [2] f7 8d [2] f1 b8 [2] df b8 [2] e0 a4 }

  condition:
    any of them
}