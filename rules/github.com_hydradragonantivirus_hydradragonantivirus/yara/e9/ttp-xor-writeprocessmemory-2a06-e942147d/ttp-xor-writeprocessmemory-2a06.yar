rule TTP_XOR_WriteProcessMemory_2a06 {
  strings:
    $key_2a06 = { 7d 74 [2] 4f 56 [2] 49 63 [2] 67 63 [2] 58 7f }

  condition:
    any of them
}