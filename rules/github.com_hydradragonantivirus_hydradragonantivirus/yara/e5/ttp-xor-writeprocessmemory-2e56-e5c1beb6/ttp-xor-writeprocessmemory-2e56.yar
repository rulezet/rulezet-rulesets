rule TTP_XOR_WriteProcessMemory_2e56 {
  strings:
    $key_2e56 = { 79 24 [2] 4b 06 [2] 4d 33 [2] 63 33 [2] 5c 2f }

  condition:
    any of them
}