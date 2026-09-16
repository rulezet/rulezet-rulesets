rule TTP_XOR_WriteProcessMemory_fc86 {
  strings:
    $key_fc86 = { ab f4 [2] 99 d6 [2] 9f e3 [2] b1 e3 [2] 8e ff }

  condition:
    any of them
}