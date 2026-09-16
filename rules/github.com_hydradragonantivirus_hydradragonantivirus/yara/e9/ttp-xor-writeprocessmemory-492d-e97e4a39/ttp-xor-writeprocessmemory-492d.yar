rule TTP_XOR_WriteProcessMemory_492d {
  strings:
    $key_492d = { 1e 5f [2] 2c 7d [2] 2a 48 [2] 04 48 [2] 3b 54 }

  condition:
    any of them
}