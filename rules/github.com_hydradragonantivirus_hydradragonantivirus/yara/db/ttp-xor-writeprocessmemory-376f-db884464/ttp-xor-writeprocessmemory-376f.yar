rule TTP_XOR_WriteProcessMemory_376f {
  strings:
    $key_376f = { 60 1d [2] 52 3f [2] 54 0a [2] 7a 0a [2] 45 16 }

  condition:
    any of them
}