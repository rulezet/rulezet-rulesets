rule TTP_XOR_WriteProcessMemory_d917 {
  strings:
    $key_d917 = { 8e 65 [2] bc 47 [2] ba 72 [2] 94 72 [2] ab 6e }

  condition:
    any of them
}