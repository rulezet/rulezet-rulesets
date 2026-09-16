rule TTP_XOR_WriteProcessMemory_cec8 {
  strings:
    $key_cec8 = { 99 ba [2] ab 98 [2] ad ad [2] 83 ad [2] bc b1 }

  condition:
    any of them
}