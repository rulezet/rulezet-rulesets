rule TTP_XOR_WriteProcessMemory_074a {
  strings:
    $key_074a = { 50 38 [2] 62 1a [2] 64 2f [2] 4a 2f [2] 75 33 }

  condition:
    any of them
}