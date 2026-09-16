rule TTP_XOR_WriteProcessMemory_003d {
  strings:
    $key_003d = { 57 4f [2] 65 6d [2] 63 58 [2] 4d 58 [2] 72 44 }

  condition:
    any of them
}