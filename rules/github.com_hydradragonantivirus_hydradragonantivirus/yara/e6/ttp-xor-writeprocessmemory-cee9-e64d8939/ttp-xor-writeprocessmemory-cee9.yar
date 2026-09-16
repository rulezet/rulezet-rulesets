rule TTP_XOR_WriteProcessMemory_cee9 {
  strings:
    $key_cee9 = { 99 9b [2] ab b9 [2] ad 8c [2] 83 8c [2] bc 90 }

  condition:
    any of them
}