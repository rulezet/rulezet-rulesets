rule TTP_XOR_WriteProcessMemory_3156 {
  strings:
    $key_3156 = { 66 24 [2] 54 06 [2] 52 33 [2] 7c 33 [2] 43 2f }

  condition:
    any of them
}