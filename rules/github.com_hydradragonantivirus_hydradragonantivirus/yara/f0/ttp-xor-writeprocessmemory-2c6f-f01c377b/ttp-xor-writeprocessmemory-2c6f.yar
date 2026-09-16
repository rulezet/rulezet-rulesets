rule TTP_XOR_WriteProcessMemory_2c6f {
  strings:
    $key_2c6f = { 7b 1d [2] 49 3f [2] 4f 0a [2] 61 0a [2] 5e 16 }

  condition:
    any of them
}