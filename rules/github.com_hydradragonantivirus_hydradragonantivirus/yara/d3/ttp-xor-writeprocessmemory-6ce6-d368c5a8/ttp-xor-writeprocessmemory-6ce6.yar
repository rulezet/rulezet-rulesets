rule TTP_XOR_WriteProcessMemory_6ce6 {
  strings:
    $key_6ce6 = { 3b 94 [2] 09 b6 [2] 0f 83 [2] 21 83 [2] 1e 9f }

  condition:
    any of them
}