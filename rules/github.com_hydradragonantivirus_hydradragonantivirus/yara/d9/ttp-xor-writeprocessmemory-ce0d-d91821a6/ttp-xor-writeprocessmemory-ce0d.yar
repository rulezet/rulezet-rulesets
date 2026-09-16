rule TTP_XOR_WriteProcessMemory_ce0d {
  strings:
    $key_ce0d = { 99 7f [2] ab 5d [2] ad 68 [2] 83 68 [2] bc 74 }

  condition:
    any of them
}