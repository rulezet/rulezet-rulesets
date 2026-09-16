rule TTP_XOR_WriteProcessMemory_270f {
  strings:
    $key_270f = { 70 7d [2] 42 5f [2] 44 6a [2] 6a 6a [2] 55 76 }

  condition:
    any of them
}