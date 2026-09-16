rule TTP_XOR_WriteProcessMemory_7476 {
  strings:
    $key_7476 = { 23 04 [2] 11 26 [2] 17 13 [2] 39 13 [2] 06 0f }

  condition:
    any of them
}