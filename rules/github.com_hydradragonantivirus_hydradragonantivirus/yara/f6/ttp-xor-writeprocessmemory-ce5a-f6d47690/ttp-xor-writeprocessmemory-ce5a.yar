rule TTP_XOR_WriteProcessMemory_ce5a {
  strings:
    $key_ce5a = { 99 28 [2] ab 0a [2] ad 3f [2] 83 3f [2] bc 23 }

  condition:
    any of them
}