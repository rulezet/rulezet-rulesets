rule TTP_XOR_WriteProcessMemory_a98f {
  strings:
    $key_a98f = { fe fd [2] cc df [2] ca ea [2] e4 ea [2] db f6 }

  condition:
    any of them
}