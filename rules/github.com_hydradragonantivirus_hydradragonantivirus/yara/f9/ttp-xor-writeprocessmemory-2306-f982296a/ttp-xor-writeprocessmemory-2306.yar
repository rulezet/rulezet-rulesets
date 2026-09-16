rule TTP_XOR_WriteProcessMemory_2306 {
  strings:
    $key_2306 = { 74 74 [2] 46 56 [2] 40 63 [2] 6e 63 [2] 51 7f }

  condition:
    any of them
}