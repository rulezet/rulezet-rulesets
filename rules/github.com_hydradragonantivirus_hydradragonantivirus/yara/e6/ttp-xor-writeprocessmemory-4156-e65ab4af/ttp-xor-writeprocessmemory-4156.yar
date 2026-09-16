rule TTP_XOR_WriteProcessMemory_4156 {
  strings:
    $key_4156 = { 16 24 [2] 24 06 [2] 22 33 [2] 0c 33 [2] 33 2f }

  condition:
    any of them
}