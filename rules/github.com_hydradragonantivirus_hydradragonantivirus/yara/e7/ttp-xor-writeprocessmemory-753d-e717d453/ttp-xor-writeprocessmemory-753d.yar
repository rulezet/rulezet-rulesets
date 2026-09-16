rule TTP_XOR_WriteProcessMemory_753d {
  strings:
    $key_753d = { 22 4f [2] 10 6d [2] 16 58 [2] 38 58 [2] 07 44 }

  condition:
    any of them
}