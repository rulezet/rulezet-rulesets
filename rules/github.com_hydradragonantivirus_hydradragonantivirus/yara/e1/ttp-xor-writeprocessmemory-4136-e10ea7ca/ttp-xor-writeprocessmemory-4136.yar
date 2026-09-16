rule TTP_XOR_WriteProcessMemory_4136 {
  strings:
    $key_4136 = { 16 44 [2] 24 66 [2] 22 53 [2] 0c 53 [2] 33 4f }

  condition:
    any of them
}