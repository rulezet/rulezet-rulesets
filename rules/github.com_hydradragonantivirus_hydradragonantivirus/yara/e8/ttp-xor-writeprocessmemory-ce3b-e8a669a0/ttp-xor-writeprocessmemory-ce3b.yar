rule TTP_XOR_WriteProcessMemory_ce3b {
  strings:
    $key_ce3b = { 99 49 [2] ab 6b [2] ad 5e [2] 83 5e [2] bc 42 }

  condition:
    any of them
}