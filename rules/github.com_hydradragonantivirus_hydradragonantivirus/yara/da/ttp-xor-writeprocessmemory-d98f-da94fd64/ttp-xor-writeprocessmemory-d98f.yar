rule TTP_XOR_WriteProcessMemory_d98f {
  strings:
    $key_d98f = { 8e fd [2] bc df [2] ba ea [2] 94 ea [2] ab f6 }

  condition:
    any of them
}