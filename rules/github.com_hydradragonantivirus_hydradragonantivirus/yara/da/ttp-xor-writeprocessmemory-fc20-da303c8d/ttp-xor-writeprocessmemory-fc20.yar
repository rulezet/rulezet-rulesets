rule TTP_XOR_WriteProcessMemory_fc20 {
  strings:
    $key_fc20 = { ab 52 [2] 99 70 [2] 9f 45 [2] b1 45 [2] 8e 59 }

  condition:
    any of them
}