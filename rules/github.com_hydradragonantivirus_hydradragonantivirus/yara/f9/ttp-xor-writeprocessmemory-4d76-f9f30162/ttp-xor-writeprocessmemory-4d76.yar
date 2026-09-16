rule TTP_XOR_WriteProcessMemory_4d76 {
  strings:
    $key_4d76 = { 1a 04 [2] 28 26 [2] 2e 13 [2] 00 13 [2] 3f 0f }

  condition:
    any of them
}