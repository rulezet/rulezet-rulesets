rule TTP_XOR_WriteProcessMemory_573d {
  strings:
    $key_573d = { 00 4f [2] 32 6d [2] 34 58 [2] 1a 58 [2] 25 44 }

  condition:
    any of them
}