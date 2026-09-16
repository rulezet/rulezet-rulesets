rule TTP_XOR_WriteProcessMemory_d931 {
  strings:
    $key_d931 = { 8e 43 [2] bc 61 [2] ba 54 [2] 94 54 [2] ab 48 }

  condition:
    any of them
}