rule TTP_XOR_WriteProcessMemory_5c36 {
  strings:
    $key_5c36 = { 0b 44 [2] 39 66 [2] 3f 53 [2] 11 53 [2] 2e 4f }

  condition:
    any of them
}