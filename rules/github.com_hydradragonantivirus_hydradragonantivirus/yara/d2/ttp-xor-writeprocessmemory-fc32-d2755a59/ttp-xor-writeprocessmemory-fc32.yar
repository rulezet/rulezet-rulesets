rule TTP_XOR_WriteProcessMemory_fc32 {
  strings:
    $key_fc32 = { ab 40 [2] 99 62 [2] 9f 57 [2] b1 57 [2] 8e 4b }

  condition:
    any of them
}