rule TTP_XOR_WriteProcessMemory_cc76 {
  strings:
    $key_cc76 = { 9b 04 [2] a9 26 [2] af 13 [2] 81 13 [2] be 0f }

  condition:
    any of them
}