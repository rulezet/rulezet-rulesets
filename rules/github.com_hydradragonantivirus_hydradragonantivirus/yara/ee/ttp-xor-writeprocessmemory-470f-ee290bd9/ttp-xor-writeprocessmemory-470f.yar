rule TTP_XOR_WriteProcessMemory_470f {
  strings:
    $key_470f = { 10 7d [2] 22 5f [2] 24 6a [2] 0a 6a [2] 35 76 }

  condition:
    any of them
}