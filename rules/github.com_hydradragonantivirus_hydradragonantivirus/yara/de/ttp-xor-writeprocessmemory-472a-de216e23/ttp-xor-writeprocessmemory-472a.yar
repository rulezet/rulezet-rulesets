rule TTP_XOR_WriteProcessMemory_472a {
  strings:
    $key_472a = { 10 58 [2] 22 7a [2] 24 4f [2] 0a 4f [2] 35 53 }

  condition:
    any of them
}