rule TTP_XOR_WriteProcessMemory_526f {
  strings:
    $key_526f = { 05 1d [2] 37 3f [2] 31 0a [2] 1f 0a [2] 20 16 }

  condition:
    any of them
}