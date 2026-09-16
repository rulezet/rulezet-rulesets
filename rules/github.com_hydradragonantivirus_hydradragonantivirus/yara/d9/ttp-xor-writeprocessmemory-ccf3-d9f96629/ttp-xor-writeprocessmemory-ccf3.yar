rule TTP_XOR_WriteProcessMemory_ccf3 {
  strings:
    $key_ccf3 = { 9b 81 [2] a9 a3 [2] af 96 [2] 81 96 [2] be 8a }

  condition:
    any of them
}