rule TTP_XOR_WriteProcessMemory_ead0 {
  strings:
    $key_ead0 = { bd a2 [2] 8f 80 [2] 89 b5 [2] a7 b5 [2] 98 a9 }

  condition:
    any of them
}