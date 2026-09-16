rule TTP_XOR_WriteProcessMemory_2e06 {
  strings:
    $key_2e06 = { 79 74 [2] 4b 56 [2] 4d 63 [2] 63 63 [2] 5c 7f }

  condition:
    any of them
}