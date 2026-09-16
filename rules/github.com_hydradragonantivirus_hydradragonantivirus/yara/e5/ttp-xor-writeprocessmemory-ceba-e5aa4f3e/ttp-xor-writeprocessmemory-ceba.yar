rule TTP_XOR_WriteProcessMemory_ceba {
  strings:
    $key_ceba = { 99 c8 [2] ab ea [2] ad df [2] 83 df [2] bc c3 }

  condition:
    any of them
}