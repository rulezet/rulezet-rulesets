rule TTP_XOR_WriteProcessMemory_e900 {
  strings:
    $key_e900 = { be 72 [2] 8c 50 [2] 8a 65 [2] a4 65 [2] 9b 79 }

  condition:
    any of them
}