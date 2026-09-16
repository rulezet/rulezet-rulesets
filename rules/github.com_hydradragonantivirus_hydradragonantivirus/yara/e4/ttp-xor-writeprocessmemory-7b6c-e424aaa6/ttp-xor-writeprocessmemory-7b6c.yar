rule TTP_XOR_WriteProcessMemory_7b6c {
  strings:
    $key_7b6c = { 2c 1e [2] 1e 3c [2] 18 09 [2] 36 09 [2] 09 15 }

  condition:
    any of them
}