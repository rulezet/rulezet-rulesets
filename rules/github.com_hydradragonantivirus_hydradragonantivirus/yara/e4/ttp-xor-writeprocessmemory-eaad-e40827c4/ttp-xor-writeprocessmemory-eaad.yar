rule TTP_XOR_WriteProcessMemory_eaad {
  strings:
    $key_eaad = { bd df [2] 8f fd [2] 89 c8 [2] a7 c8 [2] 98 d4 }

  condition:
    any of them
}