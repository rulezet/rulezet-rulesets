rule TTP_XOR_WriteProcessMemory_fc82 {
  strings:
    $key_fc82 = { ab f0 [2] 99 d2 [2] 9f e7 [2] b1 e7 [2] 8e fb }

  condition:
    any of them
}