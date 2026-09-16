rule TTP_XOR_WriteProcessMemory_656f {
  strings:
    $key_656f = { 32 1d [2] 00 3f [2] 06 0a [2] 28 0a [2] 17 16 }

  condition:
    any of them
}