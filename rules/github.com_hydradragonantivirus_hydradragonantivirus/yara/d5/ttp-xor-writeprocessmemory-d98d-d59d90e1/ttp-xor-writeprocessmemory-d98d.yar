rule TTP_XOR_WriteProcessMemory_d98d {
  strings:
    $key_d98d = { 8e ff [2] bc dd [2] ba e8 [2] 94 e8 [2] ab f4 }

  condition:
    any of them
}