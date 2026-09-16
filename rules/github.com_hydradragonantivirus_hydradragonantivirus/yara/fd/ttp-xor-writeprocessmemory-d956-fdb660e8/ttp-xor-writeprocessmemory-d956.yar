rule TTP_XOR_WriteProcessMemory_d956 {
  strings:
    $key_d956 = { 8e 24 [2] bc 06 [2] ba 33 [2] 94 33 [2] ab 2f }

  condition:
    any of them
}