rule TTP_XOR_WriteProcessMemory_596a {
  strings:
    $key_596a = { 0e 18 [2] 3c 3a [2] 3a 0f [2] 14 0f [2] 2b 13 }

  condition:
    any of them
}