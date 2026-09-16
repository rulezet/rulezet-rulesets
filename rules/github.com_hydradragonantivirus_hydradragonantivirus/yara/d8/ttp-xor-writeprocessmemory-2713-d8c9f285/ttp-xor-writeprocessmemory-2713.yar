rule TTP_XOR_WriteProcessMemory_2713 {
  strings:
    $key_2713 = { 70 61 [2] 42 43 [2] 44 76 [2] 6a 76 [2] 55 6a }

  condition:
    any of them
}