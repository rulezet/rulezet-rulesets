rule TTP_XOR_WriteProcessMemory_4ce6 {
  strings:
    $key_4ce6 = { 1b 94 [2] 29 b6 [2] 2f 83 [2] 01 83 [2] 3e 9f }

  condition:
    any of them
}