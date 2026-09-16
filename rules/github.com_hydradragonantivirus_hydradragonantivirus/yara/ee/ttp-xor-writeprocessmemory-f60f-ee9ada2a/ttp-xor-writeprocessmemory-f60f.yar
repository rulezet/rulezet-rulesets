rule TTP_XOR_WriteProcessMemory_f60f {
  strings:
    $key_f60f = { a1 7d [2] 93 5f [2] 95 6a [2] bb 6a [2] 84 76 }

  condition:
    any of them
}