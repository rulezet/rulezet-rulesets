rule TTP_XOR_WriteProcessMemory_95ff {
  strings:
    $key_95ff = { c2 8d [2] f0 af [2] f6 9a [2] d8 9a [2] e7 86 }

  condition:
    any of them
}