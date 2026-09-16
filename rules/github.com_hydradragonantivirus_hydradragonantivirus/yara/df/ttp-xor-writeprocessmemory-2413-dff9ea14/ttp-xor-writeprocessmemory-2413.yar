rule TTP_XOR_WriteProcessMemory_2413 {
  strings:
    $key_2413 = { 73 61 [2] 41 43 [2] 47 76 [2] 69 76 [2] 56 6a }

  condition:
    any of them
}