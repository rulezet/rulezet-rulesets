rule TTP_XOR_WriteProcessMemory_48f6 {
  strings:
    $key_48f6 = { 1f 84 [2] 2d a6 [2] 2b 93 [2] 05 93 [2] 3a 8f }

  condition:
    any of them
}