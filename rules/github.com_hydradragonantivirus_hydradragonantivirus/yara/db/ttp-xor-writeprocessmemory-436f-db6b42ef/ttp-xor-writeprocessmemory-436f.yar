rule TTP_XOR_WriteProcessMemory_436f {
  strings:
    $key_436f = { 14 1d [2] 26 3f [2] 20 0a [2] 0e 0a [2] 31 16 }

  condition:
    any of them
}