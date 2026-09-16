rule TTP_XOR_WriteProcessMemory_715d {
  strings:
    $key_715d = { 26 2f [2] 14 0d [2] 12 38 [2] 3c 38 [2] 03 24 }

  condition:
    any of them
}