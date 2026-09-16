rule TTP_XOR_WriteProcessMemory_95ca {
  strings:
    $key_95ca = { c2 b8 [2] f0 9a [2] f6 af [2] d8 af [2] e7 b3 }

  condition:
    any of them
}