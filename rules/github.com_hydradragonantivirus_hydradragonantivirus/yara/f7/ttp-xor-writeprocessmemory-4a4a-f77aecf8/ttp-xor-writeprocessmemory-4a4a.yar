rule TTP_XOR_WriteProcessMemory_4a4a {
  strings:
    $key_4a4a = { 1d 38 [2] 2f 1a [2] 29 2f [2] 07 2f [2] 38 33 }

  condition:
    any of them
}