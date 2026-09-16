rule TTP_XOR_WriteProcessMemory_ce49 {
  strings:
    $key_ce49 = { 99 3b [2] ab 19 [2] ad 2c [2] 83 2c [2] bc 30 }

  condition:
    any of them
}