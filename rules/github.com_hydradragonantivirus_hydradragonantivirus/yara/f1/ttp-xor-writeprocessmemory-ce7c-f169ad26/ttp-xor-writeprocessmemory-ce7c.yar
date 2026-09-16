rule TTP_XOR_WriteProcessMemory_ce7c {
  strings:
    $key_ce7c = { 99 0e [2] ab 2c [2] ad 19 [2] 83 19 [2] bc 05 }

  condition:
    any of them
}