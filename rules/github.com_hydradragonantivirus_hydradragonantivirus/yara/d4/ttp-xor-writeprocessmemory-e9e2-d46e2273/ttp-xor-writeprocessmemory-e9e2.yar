rule TTP_XOR_WriteProcessMemory_e9e2 {
  strings:
    $key_e9e2 = { be 90 [2] 8c b2 [2] 8a 87 [2] a4 87 [2] 9b 9b }

  condition:
    any of them
}