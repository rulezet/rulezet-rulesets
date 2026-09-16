rule TTP_XOR_WriteProcessMemory_8cad {
  strings:
    $key_8cad = { db df [2] e9 fd [2] ef c8 [2] c1 c8 [2] fe d4 }

  condition:
    any of them
}