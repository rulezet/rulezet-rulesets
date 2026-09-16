rule TTP_XOR_WriteProcessMemory_455d {
  strings:
    $key_455d = { 12 2f [2] 20 0d [2] 26 38 [2] 08 38 [2] 37 24 }

  condition:
    any of them
}