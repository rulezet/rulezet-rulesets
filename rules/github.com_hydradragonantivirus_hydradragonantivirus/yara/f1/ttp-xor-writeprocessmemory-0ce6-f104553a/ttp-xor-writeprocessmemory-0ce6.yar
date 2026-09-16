rule TTP_XOR_WriteProcessMemory_0ce6 {
  strings:
    $key_0ce6 = { 5b 94 [2] 69 b6 [2] 6f 83 [2] 41 83 [2] 7e 9f }

  condition:
    any of them
}