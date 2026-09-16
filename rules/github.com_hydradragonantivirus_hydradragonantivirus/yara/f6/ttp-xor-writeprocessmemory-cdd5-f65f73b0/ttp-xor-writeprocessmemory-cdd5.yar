rule TTP_XOR_WriteProcessMemory_cdd5 {
  strings:
    $key_cdd5 = { 9a a7 [2] a8 85 [2] ae b0 [2] 80 b0 [2] bf ac }

  condition:
    any of them
}