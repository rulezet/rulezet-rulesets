rule TTP_XOR_WriteProcessMemory_ce7a {
  strings:
    $key_ce7a = { 99 08 [2] ab 2a [2] ad 1f [2] 83 1f [2] bc 03 }

  condition:
    any of them
}