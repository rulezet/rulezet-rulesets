rule TTP_XOR_WriteProcessMemory_eff6 {
  strings:
    $key_eff6 = { b8 84 [2] 8a a6 [2] 8c 93 [2] a2 93 [2] 9d 8f }

  condition:
    any of them
}