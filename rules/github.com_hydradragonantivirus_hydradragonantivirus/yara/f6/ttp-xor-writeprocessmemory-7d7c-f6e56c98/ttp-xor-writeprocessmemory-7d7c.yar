rule TTP_XOR_WriteProcessMemory_7d7c {
  strings:
    $key_7d7c = { 2a 0e [2] 18 2c [2] 1e 19 [2] 30 19 [2] 0f 05 }

  condition:
    any of them
}