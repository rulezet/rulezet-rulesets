rule TTP_XOR_WriteProcessMemory_7ef6 {
  strings:
    $key_7ef6 = { 29 84 [2] 1b a6 [2] 1d 93 [2] 33 93 [2] 0c 8f }

  condition:
    any of them
}