rule TTP_XOR_WriteProcessMemory_cc62 {
  strings:
    $key_cc62 = { 9b 10 [2] a9 32 [2] af 07 [2] 81 07 [2] be 1b }

  condition:
    any of them
}