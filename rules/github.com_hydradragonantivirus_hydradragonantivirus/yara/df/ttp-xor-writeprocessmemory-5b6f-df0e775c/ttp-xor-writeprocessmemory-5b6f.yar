rule TTP_XOR_WriteProcessMemory_5b6f {
  strings:
    $key_5b6f = { 0c 1d [2] 3e 3f [2] 38 0a [2] 16 0a [2] 29 16 }

  condition:
    any of them
}