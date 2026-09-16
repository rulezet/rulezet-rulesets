rule TTP_XOR_WriteProcessMemory_7b6f {
  strings:
    $key_7b6f = { 2c 1d [2] 1e 3f [2] 18 0a [2] 36 0a [2] 09 16 }

  condition:
    any of them
}