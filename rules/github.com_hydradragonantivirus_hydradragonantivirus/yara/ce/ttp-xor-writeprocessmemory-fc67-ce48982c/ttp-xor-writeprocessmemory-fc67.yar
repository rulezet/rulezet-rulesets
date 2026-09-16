rule TTP_XOR_WriteProcessMemory_fc67 {
  strings:
    $key_fc67 = { ab 15 [2] 99 37 [2] 9f 02 [2] b1 02 [2] 8e 1e }

  condition:
    any of them
}