rule TTP_XOR_WriteProcessMemory_6d4a {
  strings:
    $key_6d4a = { 3a 38 [2] 08 1a [2] 0e 2f [2] 20 2f [2] 1f 33 }

  condition:
    any of them
}