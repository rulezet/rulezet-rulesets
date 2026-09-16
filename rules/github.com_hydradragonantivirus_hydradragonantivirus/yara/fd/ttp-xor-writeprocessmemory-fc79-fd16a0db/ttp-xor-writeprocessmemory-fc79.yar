rule TTP_XOR_WriteProcessMemory_fc79 {
  strings:
    $key_fc79 = { ab 0b [2] 99 29 [2] 9f 1c [2] b1 1c [2] 8e 00 }

  condition:
    any of them
}