rule TTP_XOR_WriteProcessMemory_fca0 {
  strings:
    $key_fca0 = { ab d2 [2] 99 f0 [2] 9f c5 [2] b1 c5 [2] 8e d9 }

  condition:
    any of them
}