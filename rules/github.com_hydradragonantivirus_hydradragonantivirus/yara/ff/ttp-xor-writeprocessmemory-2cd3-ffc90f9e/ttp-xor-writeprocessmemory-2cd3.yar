rule TTP_XOR_WriteProcessMemory_2cd3 {
  strings:
    $key_2cd3 = { 7b a1 [2] 49 83 [2] 4f b6 [2] 61 b6 [2] 5e aa }

  condition:
    any of them
}