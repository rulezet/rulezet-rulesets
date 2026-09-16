rule TTP_XOR_WriteProcessMemory_d979 {
  strings:
    $key_d979 = { 8e 0b [2] bc 29 [2] ba 1c [2] 94 1c [2] ab 00 }

  condition:
    any of them
}