rule TTP_XOR_WriteProcessMemory_ead4 {
  strings:
    $key_ead4 = { bd a6 [2] 8f 84 [2] 89 b1 [2] a7 b1 [2] 98 ad }

  condition:
    any of them
}