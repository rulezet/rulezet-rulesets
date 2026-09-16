rule TTP_XOR_WriteProcessMemory_2ff6 {
  strings:
    $key_2ff6 = { 78 84 [2] 4a a6 [2] 4c 93 [2] 62 93 [2] 5d 8f }

  condition:
    any of them
}