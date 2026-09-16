rule TTP_XOR_WriteProcessMemory_dfba {
  strings:
    $key_dfba = { 88 c8 [2] ba ea [2] bc df [2] 92 df [2] ad c3 }

  condition:
    any of them
}