rule TTP_XOR_WriteProcessMemory_d968 {
  strings:
    $key_d968 = { 8e 1a [2] bc 38 [2] ba 0d [2] 94 0d [2] ab 11 }

  condition:
    any of them
}