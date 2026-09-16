rule TTP_XOR_WriteProcessMemory_555a {
  strings:
    $key_555a = { 02 28 [2] 30 0a [2] 36 3f [2] 18 3f [2] 27 23 }

  condition:
    any of them
}