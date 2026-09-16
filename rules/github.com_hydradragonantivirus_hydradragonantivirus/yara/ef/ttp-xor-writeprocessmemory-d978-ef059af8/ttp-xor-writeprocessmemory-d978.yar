rule TTP_XOR_WriteProcessMemory_d978 {
  strings:
    $key_d978 = { 8e 0a [2] bc 28 [2] ba 1d [2] 94 1d [2] ab 01 }

  condition:
    any of them
}