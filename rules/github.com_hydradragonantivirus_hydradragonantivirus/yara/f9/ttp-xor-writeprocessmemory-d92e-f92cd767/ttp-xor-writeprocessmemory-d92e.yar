rule TTP_XOR_WriteProcessMemory_d92e {
  strings:
    $key_d92e = { 8e 5c [2] bc 7e [2] ba 4b [2] 94 4b [2] ab 57 }

  condition:
    any of them
}