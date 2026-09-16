rule TTP_XOR_WriteProcessMemory_7b0d {
  strings:
    $key_7b0d = { 2c 7f [2] 1e 5d [2] 18 68 [2] 36 68 [2] 09 74 }

  condition:
    any of them
}