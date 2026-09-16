rule TTP_XOR_WriteProcessMemory_714a {
  strings:
    $key_714a = { 26 38 [2] 14 1a [2] 12 2f [2] 3c 2f [2] 03 33 }

  condition:
    any of them
}