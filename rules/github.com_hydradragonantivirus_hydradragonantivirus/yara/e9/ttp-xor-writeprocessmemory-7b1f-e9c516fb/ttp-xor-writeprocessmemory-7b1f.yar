rule TTP_XOR_WriteProcessMemory_7b1f {
  strings:
    $key_7b1f = { 2c 6d [2] 1e 4f [2] 18 7a [2] 36 7a [2] 09 66 }

  condition:
    any of them
}