rule TTP_XOR_WriteProcessMemory_afad {
  strings:
    $key_afad = { f8 df [2] ca fd [2] cc c8 [2] e2 c8 [2] dd d4 }

  condition:
    any of them
}