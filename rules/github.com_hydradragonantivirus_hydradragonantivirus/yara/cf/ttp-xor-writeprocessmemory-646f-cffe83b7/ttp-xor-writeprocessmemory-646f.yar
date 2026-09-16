rule TTP_XOR_WriteProcessMemory_646f {
  strings:
    $key_646f = { 33 1d [2] 01 3f [2] 07 0a [2] 29 0a [2] 16 16 }

  condition:
    any of them
}