rule TTP_XOR_WriteProcessMemory_90c8 {
  strings:
    $key_90c8 = { c7 ba [2] f5 98 [2] f3 ad [2] dd ad [2] e2 b1 }

  condition:
    any of them
}