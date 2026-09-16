rule TTP_XOR_WriteProcessMemory_4106 {
  strings:
    $key_4106 = { 16 74 [2] 24 56 [2] 22 63 [2] 0c 63 [2] 33 7f }

  condition:
    any of them
}