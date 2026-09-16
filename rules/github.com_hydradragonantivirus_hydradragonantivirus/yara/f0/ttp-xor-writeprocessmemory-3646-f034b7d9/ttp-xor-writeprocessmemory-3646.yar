rule TTP_XOR_WriteProcessMemory_3646 {
  strings:
    $key_3646 = { 61 34 [2] 53 16 [2] 55 23 [2] 7b 23 [2] 44 3f }

  condition:
    any of them
}