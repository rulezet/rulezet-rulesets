rule TTP_XOR_WriteProcessMemory_d93e {
  strings:
    $key_d93e = { 8e 4c [2] bc 6e [2] ba 5b [2] 94 5b [2] ab 47 }

  condition:
    any of them
}