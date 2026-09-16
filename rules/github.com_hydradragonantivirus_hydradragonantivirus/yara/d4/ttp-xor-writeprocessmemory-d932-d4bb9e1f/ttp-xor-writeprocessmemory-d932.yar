rule TTP_XOR_WriteProcessMemory_d932 {
  strings:
    $key_d932 = { 8e 40 [2] bc 62 [2] ba 57 [2] 94 57 [2] ab 4b }

  condition:
    any of them
}