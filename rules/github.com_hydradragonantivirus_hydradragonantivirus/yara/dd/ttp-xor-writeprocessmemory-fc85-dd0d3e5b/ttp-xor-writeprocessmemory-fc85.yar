rule TTP_XOR_WriteProcessMemory_fc85 {
  strings:
    $key_fc85 = { ab f7 [2] 99 d5 [2] 9f e0 [2] b1 e0 [2] 8e fc }

  condition:
    any of them
}