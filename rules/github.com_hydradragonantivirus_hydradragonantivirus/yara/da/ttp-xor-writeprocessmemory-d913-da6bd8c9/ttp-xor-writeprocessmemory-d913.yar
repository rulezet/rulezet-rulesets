rule TTP_XOR_WriteProcessMemory_d913 {
  strings:
    $key_d913 = { 8e 61 [2] bc 43 [2] ba 76 [2] 94 76 [2] ab 6a }

  condition:
    any of them
}