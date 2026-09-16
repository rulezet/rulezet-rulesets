rule TTP_XOR_WriteProcessMemory_d963 {
  strings:
    $key_d963 = { 8e 11 [2] bc 33 [2] ba 06 [2] 94 06 [2] ab 1a }

  condition:
    any of them
}