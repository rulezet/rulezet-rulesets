rule TTP_XOR_WriteProcessMemory_d927 {
  strings:
    $key_d927 = { 8e 55 [2] bc 77 [2] ba 42 [2] 94 42 [2] ab 5e }

  condition:
    any of them
}