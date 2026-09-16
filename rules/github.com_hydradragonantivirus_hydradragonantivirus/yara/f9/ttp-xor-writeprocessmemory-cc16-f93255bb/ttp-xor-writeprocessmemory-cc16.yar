rule TTP_XOR_WriteProcessMemory_cc16 {
  strings:
    $key_cc16 = { 9b 64 [2] a9 46 [2] af 73 [2] 81 73 [2] be 6f }

  condition:
    any of them
}