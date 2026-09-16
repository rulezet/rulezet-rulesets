rule TTP_XOR_WriteProcessMemory_5836 {
  strings:
    $key_5836 = { 0f 44 [2] 3d 66 [2] 3b 53 [2] 15 53 [2] 2a 4f }

  condition:
    any of them
}