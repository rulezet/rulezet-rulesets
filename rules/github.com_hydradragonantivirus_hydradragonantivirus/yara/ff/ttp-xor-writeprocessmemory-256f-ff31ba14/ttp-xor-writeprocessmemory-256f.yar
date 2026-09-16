rule TTP_XOR_WriteProcessMemory_256f {
  strings:
    $key_256f = { 72 1d [2] 40 3f [2] 46 0a [2] 68 0a [2] 57 16 }

  condition:
    any of them
}