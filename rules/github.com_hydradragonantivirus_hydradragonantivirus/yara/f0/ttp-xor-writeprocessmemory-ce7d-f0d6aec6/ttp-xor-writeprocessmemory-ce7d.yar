rule TTP_XOR_WriteProcessMemory_ce7d {
  strings:
    $key_ce7d = { 99 0f [2] ab 2d [2] ad 18 [2] 83 18 [2] bc 04 }

  condition:
    any of them
}