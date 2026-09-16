rule TTP_XOR_WriteProcessMemory_7d56 {
  strings:
    $key_7d56 = { 2a 24 [2] 18 06 [2] 1e 33 [2] 30 33 [2] 0f 2f }

  condition:
    any of them
}