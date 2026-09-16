rule TTP_XOR_WriteProcessMemory_650f {
  strings:
    $key_650f = { 32 7d [2] 00 5f [2] 06 6a [2] 28 6a [2] 17 76 }

  condition:
    any of them
}