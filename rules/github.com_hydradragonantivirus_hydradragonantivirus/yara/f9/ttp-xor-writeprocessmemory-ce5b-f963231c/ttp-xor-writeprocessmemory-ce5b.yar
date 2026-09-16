rule TTP_XOR_WriteProcessMemory_ce5b {
  strings:
    $key_ce5b = { 99 29 [2] ab 0b [2] ad 3e [2] 83 3e [2] bc 22 }

  condition:
    any of them
}