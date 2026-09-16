rule TTP_XOR_WriteProcessMemory_e5e6 {
  strings:
    $key_e5e6 = { b2 94 [2] 80 b6 [2] 86 83 [2] a8 83 [2] 97 9f }

  condition:
    any of them
}