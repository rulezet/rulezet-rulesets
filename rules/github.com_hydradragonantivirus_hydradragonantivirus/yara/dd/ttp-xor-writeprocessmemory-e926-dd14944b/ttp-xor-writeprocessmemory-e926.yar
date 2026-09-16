rule TTP_XOR_WriteProcessMemory_e926 {
  strings:
    $key_e926 = { be 54 [2] 8c 76 [2] 8a 43 [2] a4 43 [2] 9b 5f }

  condition:
    any of them
}