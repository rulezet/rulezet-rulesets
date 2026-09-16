rule TTP_XOR_WriteProcessMemory_2553 {
  strings:
    $key_2553 = { 72 21 [2] 40 03 [2] 46 36 [2] 68 36 [2] 57 2a }

  condition:
    any of them
}