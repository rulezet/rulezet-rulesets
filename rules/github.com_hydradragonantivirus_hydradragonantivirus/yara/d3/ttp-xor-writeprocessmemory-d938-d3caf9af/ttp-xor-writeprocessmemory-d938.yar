rule TTP_XOR_WriteProcessMemory_d938 {
  strings:
    $key_d938 = { 8e 4a [2] bc 68 [2] ba 5d [2] 94 5d [2] ab 41 }

  condition:
    any of them
}