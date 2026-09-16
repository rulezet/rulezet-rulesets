rule TTP_XOR_WriteProcessMemory_435f {
  strings:
    $key_435f = { 14 2d [2] 26 0f [2] 20 3a [2] 0e 3a [2] 31 26 }

  condition:
    any of them
}