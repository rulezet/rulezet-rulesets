rule TTP_XOR_WriteProcessMemory_474a {
  strings:
    $key_474a = { 10 38 [2] 22 1a [2] 24 2f [2] 0a 2f [2] 35 33 }

  condition:
    any of them
}