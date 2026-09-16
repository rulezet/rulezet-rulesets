rule TTP_XOR_WriteProcessMemory_ce11 {
  strings:
    $key_ce11 = { 99 63 [2] ab 41 [2] ad 74 [2] 83 74 [2] bc 68 }

  condition:
    any of them
}