rule TTP_XOR_WriteProcessMemory_d9ce {
  strings:
    $key_d9ce = { 8e bc [2] bc 9e [2] ba ab [2] 94 ab [2] ab b7 }

  condition:
    any of them
}