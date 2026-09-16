rule TTP_XOR_WriteProcessMemory_95ce {
  strings:
    $key_95ce = { c2 bc [2] f0 9e [2] f6 ab [2] d8 ab [2] e7 b7 }

  condition:
    any of them
}