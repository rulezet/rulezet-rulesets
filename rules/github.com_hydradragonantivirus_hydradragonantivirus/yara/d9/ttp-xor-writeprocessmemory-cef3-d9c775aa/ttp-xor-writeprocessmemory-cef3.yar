rule TTP_XOR_WriteProcessMemory_cef3 {
  strings:
    $key_cef3 = { 99 81 [2] ab a3 [2] ad 96 [2] 83 96 [2] bc 8a }

  condition:
    any of them
}