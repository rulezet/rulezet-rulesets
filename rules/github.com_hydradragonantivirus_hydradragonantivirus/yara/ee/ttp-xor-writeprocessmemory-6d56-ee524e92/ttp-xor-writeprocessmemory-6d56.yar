rule TTP_XOR_WriteProcessMemory_6d56 {
  strings:
    $key_6d56 = { 3a 24 [2] 08 06 [2] 0e 33 [2] 20 33 [2] 1f 2f }

  condition:
    any of them
}