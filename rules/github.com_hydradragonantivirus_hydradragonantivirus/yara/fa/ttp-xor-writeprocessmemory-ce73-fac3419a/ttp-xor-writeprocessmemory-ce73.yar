rule TTP_XOR_WriteProcessMemory_ce73 {
  strings:
    $key_ce73 = { 99 01 [2] ab 23 [2] ad 16 [2] 83 16 [2] bc 0a }

  condition:
    any of them
}