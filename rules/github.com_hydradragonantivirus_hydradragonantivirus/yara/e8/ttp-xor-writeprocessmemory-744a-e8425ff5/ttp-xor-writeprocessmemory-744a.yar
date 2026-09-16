rule TTP_XOR_WriteProcessMemory_744a {
  strings:
    $key_744a = { 23 38 [2] 11 1a [2] 17 2f [2] 39 2f [2] 06 33 }

  condition:
    any of them
}