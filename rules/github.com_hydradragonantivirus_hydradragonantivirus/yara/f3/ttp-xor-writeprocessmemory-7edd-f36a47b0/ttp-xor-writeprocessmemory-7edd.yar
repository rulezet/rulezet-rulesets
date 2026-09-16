rule TTP_XOR_WriteProcessMemory_7edd {
  strings:
    $key_7edd = { 29 af [2] 1b 8d [2] 1d b8 [2] 33 b8 [2] 0c a4 }

  condition:
    any of them
}