rule TTP_XOR_WriteProcessMemory_7e56 {
  strings:
    $key_7e56 = { 29 24 [2] 1b 06 [2] 1d 33 [2] 33 33 [2] 0c 2f }

  condition:
    any of them
}