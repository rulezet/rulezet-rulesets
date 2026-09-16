rule TTP_XOR_WriteProcessMemory_494d {
  strings:
    $key_494d = { 1e 3f [2] 2c 1d [2] 2a 28 [2] 04 28 [2] 3b 34 }

  condition:
    any of them
}