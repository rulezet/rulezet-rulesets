rule TTP_XOR_WriteProcessMemory_524a {
  strings:
    $key_524a = { 05 38 [2] 37 1a [2] 31 2f [2] 1f 2f [2] 20 33 }

  condition:
    any of them
}