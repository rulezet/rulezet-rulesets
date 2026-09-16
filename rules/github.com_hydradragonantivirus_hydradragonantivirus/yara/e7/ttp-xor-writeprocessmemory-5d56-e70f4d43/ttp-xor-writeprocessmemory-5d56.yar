rule TTP_XOR_WriteProcessMemory_5d56 {
  strings:
    $key_5d56 = { 0a 24 [2] 38 06 [2] 3e 33 [2] 10 33 [2] 2f 2f }

  condition:
    any of them
}