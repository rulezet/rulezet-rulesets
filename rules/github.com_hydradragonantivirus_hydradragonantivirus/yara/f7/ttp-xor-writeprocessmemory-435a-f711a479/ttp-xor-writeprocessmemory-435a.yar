rule TTP_XOR_WriteProcessMemory_435a {
  strings:
    $key_435a = { 14 28 [2] 26 0a [2] 20 3f [2] 0e 3f [2] 31 23 }

  condition:
    any of them
}