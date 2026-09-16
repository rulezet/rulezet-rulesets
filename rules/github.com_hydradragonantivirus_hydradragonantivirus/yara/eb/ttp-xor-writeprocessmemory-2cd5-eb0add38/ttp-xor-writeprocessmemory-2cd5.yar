rule TTP_XOR_WriteProcessMemory_2cd5 {
  strings:
    $key_2cd5 = { 7b a7 [2] 49 85 [2] 4f b0 [2] 61 b0 [2] 5e ac }

  condition:
    any of them
}