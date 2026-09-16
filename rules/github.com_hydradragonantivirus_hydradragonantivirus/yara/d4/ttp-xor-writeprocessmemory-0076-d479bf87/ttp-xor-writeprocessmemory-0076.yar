rule TTP_XOR_WriteProcessMemory_0076 {
  strings:
    $key_0076 = { 57 04 [2] 65 26 [2] 63 13 [2] 4d 13 [2] 72 0f }

  condition:
    any of them
}