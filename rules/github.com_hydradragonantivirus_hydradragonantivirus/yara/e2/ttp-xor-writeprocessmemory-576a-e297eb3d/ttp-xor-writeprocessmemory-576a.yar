rule TTP_XOR_WriteProcessMemory_576a {
  strings:
    $key_576a = { 00 18 [2] 32 3a [2] 34 0f [2] 1a 0f [2] 25 13 }

  condition:
    any of them
}