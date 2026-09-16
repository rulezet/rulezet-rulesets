rule TTP_XOR_WriteProcessMemory_ce3c {
  strings:
    $key_ce3c = { 99 4e [2] ab 6c [2] ad 59 [2] 83 59 [2] bc 45 }

  condition:
    any of them
}