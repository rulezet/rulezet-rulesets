rule TTP_XOR_WriteProcessMemory_94ad {
  strings:
    $key_94ad = { c3 df [2] f1 fd [2] f7 c8 [2] d9 c8 [2] e6 d4 }

  condition:
    any of them
}