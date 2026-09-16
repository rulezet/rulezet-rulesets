rule TTP_XOR_WriteProcessMemory_92c8 {
  strings:
    $key_92c8 = { c5 ba [2] f7 98 [2] f1 ad [2] df ad [2] e0 b1 }

  condition:
    any of them
}