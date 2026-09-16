rule TTP_XOR_WriteProcessMemory_d94b {
  strings:
    $key_d94b = { 8e 39 [2] bc 1b [2] ba 2e [2] 94 2e [2] ab 32 }

  condition:
    any of them
}