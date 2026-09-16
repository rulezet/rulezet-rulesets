rule TTP_XOR_WriteProcessMemory_2ce6 {
  strings:
    $key_2ce6 = { 7b 94 [2] 49 b6 [2] 4f 83 [2] 61 83 [2] 5e 9f }

  condition:
    any of them
}