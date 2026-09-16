rule TTP_XOR_WriteProcessMemory_0476 {
  strings:
    $key_0476 = { 53 04 [2] 61 26 [2] 67 13 [2] 49 13 [2] 76 0f }

  condition:
    any of them
}