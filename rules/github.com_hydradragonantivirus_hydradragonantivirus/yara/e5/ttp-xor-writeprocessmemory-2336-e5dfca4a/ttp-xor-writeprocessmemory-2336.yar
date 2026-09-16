rule TTP_XOR_WriteProcessMemory_2336 {
  strings:
    $key_2336 = { 74 44 [2] 46 66 [2] 40 53 [2] 6e 53 [2] 51 4f }

  condition:
    any of them
}