rule TTP_XOR_WriteProcessMemory_2068 {
  strings:
    $key_2068 = { 77 1a [2] 45 38 [2] 43 0d [2] 6d 0d [2] 52 11 }

  condition:
    any of them
}