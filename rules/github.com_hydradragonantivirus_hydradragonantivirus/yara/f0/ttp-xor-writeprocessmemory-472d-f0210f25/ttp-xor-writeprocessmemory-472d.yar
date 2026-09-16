rule TTP_XOR_WriteProcessMemory_472d {
  strings:
    $key_472d = { 10 5f [2] 22 7d [2] 24 48 [2] 0a 48 [2] 35 54 }

  condition:
    any of them
}