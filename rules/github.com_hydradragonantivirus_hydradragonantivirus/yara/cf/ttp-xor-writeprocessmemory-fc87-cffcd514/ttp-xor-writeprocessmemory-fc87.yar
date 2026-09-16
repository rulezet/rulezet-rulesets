rule TTP_XOR_WriteProcessMemory_fc87 {
  strings:
    $key_fc87 = { ab f5 [2] 99 d7 [2] 9f e2 [2] b1 e2 [2] 8e fe }

  condition:
    any of them
}