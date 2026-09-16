rule TTP_XOR_WriteProcessMemory_d046 {
  strings:
    $key_d046 = { 87 34 [2] b5 16 [2] b3 23 [2] 9d 23 [2] a2 3f }

  condition:
    any of them
}