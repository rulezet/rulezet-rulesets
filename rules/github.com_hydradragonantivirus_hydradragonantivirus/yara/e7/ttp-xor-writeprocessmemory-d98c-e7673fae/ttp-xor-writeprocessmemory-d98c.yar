rule TTP_XOR_WriteProcessMemory_d98c {
  strings:
    $key_d98c = { 8e fe [2] bc dc [2] ba e9 [2] 94 e9 [2] ab f5 }

  condition:
    any of them
}