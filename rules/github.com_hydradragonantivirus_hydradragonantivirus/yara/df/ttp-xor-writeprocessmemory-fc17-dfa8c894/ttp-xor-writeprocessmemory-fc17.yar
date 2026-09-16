rule TTP_XOR_WriteProcessMemory_fc17 {
  strings:
    $key_fc17 = { ab 65 [2] 99 47 [2] 9f 72 [2] b1 72 [2] 8e 6e }

  condition:
    any of them
}