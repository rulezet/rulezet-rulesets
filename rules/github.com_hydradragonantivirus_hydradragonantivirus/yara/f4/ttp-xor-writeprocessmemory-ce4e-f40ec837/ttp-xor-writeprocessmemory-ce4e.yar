rule TTP_XOR_WriteProcessMemory_ce4e {
  strings:
    $key_ce4e = { 99 3c [2] ab 1e [2] ad 2b [2] 83 2b [2] bc 37 }

  condition:
    any of them
}