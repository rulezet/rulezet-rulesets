rule TTP_XOR_WriteProcessMemory_d940 {
  strings:
    $key_d940 = { 8e 32 [2] bc 10 [2] ba 25 [2] 94 25 [2] ab 39 }

  condition:
    any of them
}