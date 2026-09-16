rule TTP_XOR_WriteProcessMemory_491f {
  strings:
    $key_491f = { 1e 6d [2] 2c 4f [2] 2a 7a [2] 04 7a [2] 3b 66 }

  condition:
    any of them
}