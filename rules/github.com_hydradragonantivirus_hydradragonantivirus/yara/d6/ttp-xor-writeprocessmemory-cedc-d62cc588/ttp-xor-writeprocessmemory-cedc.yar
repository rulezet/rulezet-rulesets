rule TTP_XOR_WriteProcessMemory_cedc {
  strings:
    $key_cedc = { 99 ae [2] ab 8c [2] ad b9 [2] 83 b9 [2] bc a5 }

  condition:
    any of them
}