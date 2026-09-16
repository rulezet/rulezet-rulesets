rule TTP_XOR_WriteProcessMemory_d91b {
  strings:
    $key_d91b = { 8e 69 [2] bc 4b [2] ba 7e [2] 94 7e [2] ab 62 }

  condition:
    any of them
}