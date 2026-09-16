rule TTP_XOR_WriteProcessMemory_572a {
  strings:
    $key_572a = { 00 58 [2] 32 7a [2] 34 4f [2] 1a 4f [2] 25 53 }

  condition:
    any of them
}