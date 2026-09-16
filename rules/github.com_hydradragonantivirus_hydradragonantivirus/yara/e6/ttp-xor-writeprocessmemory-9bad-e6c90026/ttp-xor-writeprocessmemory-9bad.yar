rule TTP_XOR_WriteProcessMemory_9bad {
  strings:
    $key_9bad = { cc df [2] fe fd [2] f8 c8 [2] d6 c8 [2] e9 d4 }

  condition:
    any of them
}