rule TTP_XOR_WriteProcessMemory_7b5b {
  strings:
    $key_7b5b = { 2c 29 [2] 1e 0b [2] 18 3e [2] 36 3e [2] 09 22 }

  condition:
    any of them
}