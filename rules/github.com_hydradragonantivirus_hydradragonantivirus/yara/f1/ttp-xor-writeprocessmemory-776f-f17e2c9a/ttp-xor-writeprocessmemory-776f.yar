rule TTP_XOR_WriteProcessMemory_776f {
  strings:
    $key_776f = { 20 1d [2] 12 3f [2] 14 0a [2] 3a 0a [2] 05 16 }

  condition:
    any of them
}