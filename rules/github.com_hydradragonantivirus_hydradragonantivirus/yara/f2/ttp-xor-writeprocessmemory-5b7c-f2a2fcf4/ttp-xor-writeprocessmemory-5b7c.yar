rule TTP_XOR_WriteProcessMemory_5b7c {
  strings:
    $key_5b7c = { 0c 0e [2] 3e 2c [2] 38 19 [2] 16 19 [2] 29 05 }

  condition:
    any of them
}