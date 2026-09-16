rule TTP_XOR_WriteProcessMemory_73dd {
  strings:
    $key_73dd = { 24 af [2] 16 8d [2] 10 b8 [2] 3e b8 [2] 01 a4 }

  condition:
    any of them
}