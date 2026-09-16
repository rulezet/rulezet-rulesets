rule TTP_XOR_WriteProcessMemory_7b5f {
  strings:
    $key_7b5f = { 2c 2d [2] 1e 0f [2] 18 3a [2] 36 3a [2] 09 26 }

  condition:
    any of them
}