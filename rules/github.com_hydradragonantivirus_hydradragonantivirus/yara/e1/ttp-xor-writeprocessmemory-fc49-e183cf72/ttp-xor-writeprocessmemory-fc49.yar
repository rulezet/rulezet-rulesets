rule TTP_XOR_WriteProcessMemory_fc49 {
  strings:
    $key_fc49 = { ab 3b [2] 99 19 [2] 9f 2c [2] b1 2c [2] 8e 30 }

  condition:
    any of them
}