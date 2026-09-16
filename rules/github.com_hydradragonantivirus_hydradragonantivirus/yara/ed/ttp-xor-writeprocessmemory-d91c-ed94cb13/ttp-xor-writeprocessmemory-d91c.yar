rule TTP_XOR_WriteProcessMemory_d91c {
  strings:
    $key_d91c = { 8e 6e [2] bc 4c [2] ba 79 [2] 94 79 [2] ab 65 }

  condition:
    any of them
}