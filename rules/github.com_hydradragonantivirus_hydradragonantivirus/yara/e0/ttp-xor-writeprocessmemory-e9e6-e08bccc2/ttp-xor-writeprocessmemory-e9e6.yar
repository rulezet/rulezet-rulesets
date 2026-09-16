rule TTP_XOR_WriteProcessMemory_e9e6 {
  strings:
    $key_e9e6 = { be 94 [2] 8c b6 [2] 8a 83 [2] a4 83 [2] 9b 9f }

  condition:
    any of them
}