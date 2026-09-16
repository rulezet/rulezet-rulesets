rule TTP_XOR_WriteProcessMemory_5843 {
  strings:
    $key_5843 = { 0f 31 [2] 3d 13 [2] 3b 26 [2] 15 26 [2] 2a 3a }

  condition:
    any of them
}