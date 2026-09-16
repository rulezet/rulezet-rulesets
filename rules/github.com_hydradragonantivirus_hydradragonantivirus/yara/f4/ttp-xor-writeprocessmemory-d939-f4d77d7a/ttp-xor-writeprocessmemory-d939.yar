rule TTP_XOR_WriteProcessMemory_d939 {
  strings:
    $key_d939 = { 8e 4b [2] bc 69 [2] ba 5c [2] 94 5c [2] ab 40 }

  condition:
    any of them
}