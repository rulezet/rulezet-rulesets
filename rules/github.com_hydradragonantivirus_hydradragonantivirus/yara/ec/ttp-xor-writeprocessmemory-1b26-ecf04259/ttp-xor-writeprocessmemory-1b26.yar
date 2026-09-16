rule TTP_XOR_WriteProcessMemory_1b26 {
  strings:
    $key_1b26 = { 4c 54 [2] 7e 76 [2] 78 43 [2] 56 43 [2] 69 5f }

  condition:
    any of them
}