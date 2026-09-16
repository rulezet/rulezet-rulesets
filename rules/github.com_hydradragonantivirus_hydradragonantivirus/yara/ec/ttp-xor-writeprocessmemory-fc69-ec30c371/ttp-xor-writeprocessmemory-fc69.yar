rule TTP_XOR_WriteProcessMemory_fc69 {
  strings:
    $key_fc69 = { ab 1b [2] 99 39 [2] 9f 0c [2] b1 0c [2] 8e 10 }

  condition:
    any of them
}