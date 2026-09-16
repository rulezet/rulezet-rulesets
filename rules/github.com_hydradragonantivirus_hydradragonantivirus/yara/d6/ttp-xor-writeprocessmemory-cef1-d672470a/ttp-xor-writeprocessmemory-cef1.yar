rule TTP_XOR_WriteProcessMemory_cef1 {
  strings:
    $key_cef1 = { 99 83 [2] ab a1 [2] ad 94 [2] 83 94 [2] bc 88 }

  condition:
    any of them
}