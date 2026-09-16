rule TTP_XOR_WriteProcessMemory_cee8 {
  strings:
    $key_cee8 = { 99 9a [2] ab b8 [2] ad 8d [2] 83 8d [2] bc 91 }

  condition:
    any of them
}