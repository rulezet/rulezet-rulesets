rule TTP_XOR_WriteProcessMemory_ead6 {
  strings:
    $key_ead6 = { bd a4 [2] 8f 86 [2] 89 b3 [2] a7 b3 [2] 98 af }

  condition:
    any of them
}