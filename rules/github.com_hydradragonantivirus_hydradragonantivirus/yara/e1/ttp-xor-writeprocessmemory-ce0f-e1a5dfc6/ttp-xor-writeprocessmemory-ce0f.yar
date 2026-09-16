rule TTP_XOR_WriteProcessMemory_ce0f {
  strings:
    $key_ce0f = { 99 7d [2] ab 5f [2] ad 6a [2] 83 6a [2] bc 76 }

  condition:
    any of them
}