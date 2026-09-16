rule TTP_XOR_WriteProcessMemory_643d {
  strings:
    $key_643d = { 33 4f [2] 01 6d [2] 07 58 [2] 29 58 [2] 16 44 }

  condition:
    any of them
}