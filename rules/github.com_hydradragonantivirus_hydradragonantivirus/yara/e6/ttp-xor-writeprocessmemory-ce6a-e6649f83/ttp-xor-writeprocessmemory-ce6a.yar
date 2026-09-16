rule TTP_XOR_WriteProcessMemory_ce6a {
  strings:
    $key_ce6a = { 99 18 [2] ab 3a [2] ad 0f [2] 83 0f [2] bc 13 }

  condition:
    any of them
}