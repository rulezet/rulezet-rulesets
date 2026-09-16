rule TTP_XOR_WriteProcessMemory_d948 {
  strings:
    $key_d948 = { 8e 3a [2] bc 18 [2] ba 2d [2] 94 2d [2] ab 31 }

  condition:
    any of them
}