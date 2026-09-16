rule TTP_XOR_WriteProcessMemory_819c {
  strings:
    $key_819c = { d6 ee [2] e4 cc [2] e2 f9 [2] cc f9 [2] f3 e5 }

  condition:
    any of them
}