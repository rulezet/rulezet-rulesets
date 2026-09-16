rule TTP_XOR_WriteProcessMemory_230f {
  strings:
    $key_230f = { 74 7d [2] 46 5f [2] 40 6a [2] 6e 6a [2] 51 76 }

  condition:
    any of them
}