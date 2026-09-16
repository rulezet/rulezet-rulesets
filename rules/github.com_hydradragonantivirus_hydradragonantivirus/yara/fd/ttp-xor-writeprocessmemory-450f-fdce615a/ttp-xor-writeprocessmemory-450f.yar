rule TTP_XOR_WriteProcessMemory_450f {
  strings:
    $key_450f = { 12 7d [2] 20 5f [2] 26 6a [2] 08 6a [2] 37 76 }

  condition:
    any of them
}