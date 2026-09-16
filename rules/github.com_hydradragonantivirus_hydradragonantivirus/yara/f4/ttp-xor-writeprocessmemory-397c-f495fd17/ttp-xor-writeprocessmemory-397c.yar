rule TTP_XOR_WriteProcessMemory_397c {
  strings:
    $key_397c = { 6e 0e [2] 5c 2c [2] 5a 19 [2] 74 19 [2] 4b 05 }

  condition:
    any of them
}