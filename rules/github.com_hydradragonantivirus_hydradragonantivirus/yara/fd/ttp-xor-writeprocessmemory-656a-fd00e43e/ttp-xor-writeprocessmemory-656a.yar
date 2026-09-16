rule TTP_XOR_WriteProcessMemory_656a {
  strings:
    $key_656a = { 32 18 [2] 00 3a [2] 06 0f [2] 28 0f [2] 17 13 }

  condition:
    any of them
}