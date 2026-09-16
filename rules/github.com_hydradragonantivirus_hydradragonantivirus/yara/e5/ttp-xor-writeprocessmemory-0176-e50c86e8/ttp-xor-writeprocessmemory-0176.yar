rule TTP_XOR_WriteProcessMemory_0176 {
  strings:
    $key_0176 = { 56 04 [2] 64 26 [2] 62 13 [2] 4c 13 [2] 73 0f }

  condition:
    any of them
}